const vga = @import("../drivers/vga.zig");
const process = @import("process.zig");
const timer = @import("../timer/timer.zig");
const smp = @import("../smp/smp.zig");

pub const SchedulerType = enum {
    RoundRobin,
    Priority,
    MultiLevelFeedback,
};

pub const Priority = enum(u8) {
    Idle = 0,
    Low = 1,
    Normal = 2,
    High = 3,
    RealTime = 4,
};

pub const SchedulerStats = struct {
    context_switches: u64,
    total_processes: u32,
    ready_processes: u32,
    blocked_processes: u32,
    cpu_usage_percent: u32,
};

const TimeQuantum = struct {
    priority: Priority,
    ticks: u32,
};

const QUANTUM_TABLE = [_]TimeQuantum{
    .{ .priority = .Idle, .ticks = 1 },
    .{ .priority = .Low, .ticks = 5 },
    .{ .priority = .Normal, .ticks = 10 },
    .{ .priority = .High, .ticks = 15 },
    .{ .priority = .RealTime, .ticks = 20 },
};

const MAX_EXTENDED_PROCESSES = 256;
const MAX_SCHED_CPUS = 16;
const RUN_QUEUE_INDEX: i8 = 5;
const NO_QUEUE_INDEX: i8 = -1;

pub const ProcessExtended = struct {
    base: *process.Process,
    priority: Priority,
    original_priority: Priority,
    time_quantum: u32,
    time_used: u32,
    total_runtime: u64,
    last_scheduled: u64,
    nice_value: i8,
    cpu_affinity: u32,
    wait_time: u64,
    response_time: u64,
    turnaround_time: u64,
    assigned_cpu: u32,
    in_use: bool,
    ready_next: ?*ProcessExtended,
    ready_prev: ?*ProcessExtended,
    queue_index: i8,
};

const ReadyQueue = struct {
    head: ?*ProcessExtended = null,
    tail: ?*ProcessExtended = null,
};

// SAFETY: all entries initialized in init() before use
var extended_processes: [MAX_EXTENDED_PROCESSES]ProcessExtended = undefined;
var scheduler_type: SchedulerType = .RoundRobin;
var stats: SchedulerStats = .{
    .context_switches = 0,
    .total_processes = 0,
    .ready_processes = 0,
    .blocked_processes = 0,
    .cpu_usage_percent = 0,
};

var current_extended: [MAX_SCHED_CPUS]?*ProcessExtended = [_]?*ProcessExtended{null} ** MAX_SCHED_CPUS;
var ready_queues: [MAX_SCHED_CPUS][5]ReadyQueue = [_][5]ReadyQueue{
    [_]ReadyQueue{ .{}, .{}, .{}, .{}, .{} },
} ** MAX_SCHED_CPUS;
var run_queue: [MAX_SCHED_CPUS]ReadyQueue = [_]ReadyQueue{.{}} ** MAX_SCHED_CPUS;
var idle_time: [MAX_SCHED_CPUS]u64 = [_]u64{0} ** MAX_SCHED_CPUS;
var busy_time: [MAX_SCHED_CPUS]u64 = [_]u64{0} ** MAX_SCHED_CPUS;

var mlfq_boost_counter: [MAX_SCHED_CPUS]u32 = [_]u32{0} ** MAX_SCHED_CPUS;
var next_cpu_rr: u32 = 0;
const MLFQ_BOOST_INTERVAL: u32 = 50;

fn getQuantumForPriority(priority: Priority) u32 {
    for (QUANTUM_TABLE) |quantum| {
        if (quantum.priority == priority) {
            return quantum.ticks;
        }
    }
    return 10;
}

fn clampCPU(cpu_id: u32) usize {
    return @min(@as(usize, @intCast(cpu_id)), MAX_SCHED_CPUS - 1);
}

fn activeCPUCount() u32 {
    if (!smp.isSMPEnabled()) return 1;
    const n = smp.getNumCPUs();
    if (n == 0) return 1;
    return @min(n, MAX_SCHED_CPUS);
}

fn chooseCPUForNewProcess() u32 {
    const cpu_count = activeCPUCount();
    const target = next_cpu_rr % cpu_count;
    next_cpu_rr = (next_cpu_rr + 1) % cpu_count;
    return target;
}

fn queueForIndex(queue_index: i8, cpu_id: u32) ?*ReadyQueue {
    const cpu_idx = clampCPU(cpu_id);
    if (queue_index == RUN_QUEUE_INDEX) {
        return &run_queue[cpu_idx];
    }

    if (queue_index >= 0) {
        const idx: usize = @intCast(queue_index);
        if (idx < ready_queues[cpu_idx].len) {
            return &ready_queues[cpu_idx][idx];
        }
    }

    return null;
}

fn enqueueInQueue(queue: *ReadyQueue, ext: *ProcessExtended, queue_index: i8) void {
    if (ext.queue_index != NO_QUEUE_INDEX) {
        dequeueFromQueue(ext);
    }

    ext.ready_prev = queue.tail;
    ext.ready_next = null;

    if (queue.tail) |tail| {
        tail.ready_next = ext;
    } else {
        queue.head = ext;
    }

    queue.tail = ext;
    ext.queue_index = queue_index;
}

fn dequeueFromQueue(ext: *ProcessExtended) void {
    const queue = queueForIndex(ext.queue_index, ext.assigned_cpu) orelse {
        ext.ready_next = null;
        ext.ready_prev = null;
        ext.queue_index = NO_QUEUE_INDEX;
        return;
    };

    const is_member = (queue.head == ext) or (queue.tail == ext) or (ext.ready_prev != null) or (ext.ready_next != null);
    if (!is_member) {
        ext.ready_next = null;
        ext.ready_prev = null;
        ext.queue_index = NO_QUEUE_INDEX;
        return;
    }

    if (ext.ready_prev) |prev| {
        prev.ready_next = ext.ready_next;
    } else {
        queue.head = ext.ready_next;
    }

    if (ext.ready_next) |next| {
        next.ready_prev = ext.ready_prev;
    } else {
        queue.tail = ext.ready_prev;
    }

    ext.ready_next = null;
    ext.ready_prev = null;
    ext.queue_index = NO_QUEUE_INDEX;
}

fn targetQueueIndex(ext: *const ProcessExtended) i8 {
    return switch (scheduler_type) {
        .RoundRobin => RUN_QUEUE_INDEX,
        .Priority, .MultiLevelFeedback => @as(i8, @intCast(@intFromEnum(ext.priority))),
    };
}

fn rebuildQueues() void {
    for (&run_queue) |*queue| {
        queue.* = .{};
    }
    for (&ready_queues) |*cpu_queues| {
        for (cpu_queues) |*queue| {
            queue.* = .{};
        }
    }

    for (&extended_processes) |*ext| {
        ext.ready_next = null;
        ext.ready_prev = null;
        ext.queue_index = NO_QUEUE_INDEX;
    }

    for (&extended_processes) |*ext| {
        if (!ext.in_use or ext.base.state == .Terminated) {
            continue;
        }

        const queue_index = targetQueueIndex(ext);
        if (queueForIndex(queue_index, ext.assigned_cpu)) |queue| {
            enqueueInQueue(queue, ext, queue_index);
        }
    }
}

fn addToReadyQueue(new_ext: *ProcessExtended) void {
    new_ext.base.state = .Ready;

    const queue_index = targetQueueIndex(new_ext);
    if (queueForIndex(queue_index, new_ext.assigned_cpu)) |queue| {
        enqueueInQueue(queue, new_ext, queue_index);
    }

    stats.ready_processes += 1;
}

fn isRunnable(ext: *const ProcessExtended) bool {
    return ext.base.state == .Ready or ext.base.state == .Running;
}

fn findRunnableFrom(start: ?*ProcessExtended) ?*ProcessExtended {
    var current = start;
    while (current) |ext| {
        if (isRunnable(ext)) {
            return ext;
        }
        current = ext.ready_next;
    }
    return null;
}

fn findRunnableFallback() ?*process.Process {
    if (process.process_list_head) |head| {
        var current = head;
        while (current.state != .Ready and current.state != .Running) {
            if (current.next) |next_proc| {
                current = next_proc;
            } else {
                break;
            }
        }
        if (current.state == .Ready or current.state == .Running) {
            return current;
        }
    }
    return null;
}

fn moveProcessForPriorityChange(ext: *ProcessExtended, old_priority: Priority, new_priority: Priority) void {
    if (old_priority == new_priority) return;
    if (scheduler_type == .RoundRobin) return;
    if (ext.queue_index == NO_QUEUE_INDEX) return;

    const new_queue_index: i8 = @intCast(@intFromEnum(new_priority));
    if (ext.queue_index == new_queue_index) return;

    dequeueFromQueue(ext);
    if (queueForIndex(new_queue_index, ext.assigned_cpu)) |queue| {
        enqueueInQueue(queue, ext, new_queue_index);
    }
}

pub fn init() void {
    vga.print("Initializing advanced scheduler...\n");

    for (&extended_processes) |*ext| {
        ext.in_use = false;
        ext.priority = .Normal;
        ext.time_quantum = 10;
        ext.time_used = 0;
        ext.total_runtime = 0;
        ext.last_scheduled = 0;
        ext.nice_value = 0;
        ext.cpu_affinity = 0xFFFFFFFF;
        ext.wait_time = 0;
        ext.response_time = 0;
        ext.turnaround_time = 0;
        ext.assigned_cpu = 0;
        ext.ready_next = null;
        ext.ready_prev = null;
        ext.queue_index = NO_QUEUE_INDEX;
    }

    scheduler_type = .RoundRobin;
    for (&run_queue) |*queue| {
        queue.* = .{};
    }
    for (&ready_queues) |*cpu_queues| {
        for (cpu_queues) |*queue| {
            queue.* = .{};
        }
    }

    for (&current_extended) |*curr| {
        curr.* = null;
    }
    @memset(idle_time[0..], 0);
    @memset(busy_time[0..], 0);
    @memset(mlfq_boost_counter[0..], 0);
    next_cpu_rr = 0;
    stats = .{
        .context_switches = 0,
        .total_processes = 0,
        .ready_processes = 0,
        .blocked_processes = 0,
        .cpu_usage_percent = 0,
    };

    vga.print("Scheduler initialized with Round Robin algorithm\n");
}

pub fn setSchedulerType(sched_type: SchedulerType) void {
    scheduler_type = sched_type;
    rebuildQueues();

    vga.print("Scheduler changed to: ");
    switch (sched_type) {
        .RoundRobin => vga.print("Round Robin"),
        .Priority => vga.print("Priority"),
        .MultiLevelFeedback => vga.print("Multi-Level Feedback Queue"),
    }
    vga.print("\n");
}

pub fn registerProcess(proc: *process.Process, priority: Priority) *ProcessExtended {
    for (&extended_processes, 0..) |*ext, idx| {
        if (!ext.in_use) {
            ext.base = proc;
            ext.priority = priority;
            ext.original_priority = priority;
            ext.time_quantum = getQuantumForPriority(priority);
            ext.time_used = 0;
            ext.total_runtime = 0;
            ext.last_scheduled = timer.getTicks();
            ext.nice_value = 0;
            ext.wait_time = 0;
            ext.response_time = 0;
            ext.turnaround_time = 0;
            ext.assigned_cpu = chooseCPUForNewProcess();
            ext.ready_next = null;
            ext.ready_prev = null;
            ext.queue_index = NO_QUEUE_INDEX;
            ext.in_use = true;

            proc.extended_idx = @intCast(idx);

            addToReadyQueue(ext);
            stats.total_processes += 1;

            return ext;
        }
    }

    vga.print("Warning: No space for extended process info\n");
    return &extended_processes[0];
}

pub export fn schedule() ?*process.Process {
    return scheduleForCPU(smp.getCurrentCPU());
}

pub fn scheduleForCPU(cpu_id_in: u32) ?*process.Process {
    const cpu_id = @as(u32, @intCast(clampCPU(cpu_id_in)));
    const next = switch (scheduler_type) {
        .RoundRobin => scheduleRoundRobin(cpu_id),
        .Priority => schedulePriority(cpu_id),
        .MultiLevelFeedback => scheduleMLFQ(cpu_id),
    } orelse stealRunnable(cpu_id);

    if (next) |ext| {
        const cpu_idx = clampCPU(cpu_id);
        busy_time[cpu_idx] += 1;
        ext.total_runtime += 1;

        if (current_extended[cpu_idx] != ext) {
            stats.context_switches += 1;

            if (current_extended[cpu_idx]) |curr| {
                curr.time_used = 0;
                curr.wait_time = timer.getTicks();
            }

            ext.last_scheduled = timer.getTicks();
            if (ext.response_time == 0) {
                ext.response_time = timer.getTicks();
            }

            current_extended[cpu_idx] = ext;
        }

        updateStatistics(cpu_id);
        return ext.base;
    }

    if (findRunnableFallback()) |fallback| {
        busy_time[clampCPU(cpu_id)] += 1;
        updateStatistics(cpu_id);
        return fallback;
    }

    idle_time[clampCPU(cpu_id)] += 1;
    updateStatistics(cpu_id);
    return null;
}

fn scheduleRoundRobin(cpu_id: u32) ?*ProcessExtended {
    const cpu_idx = clampCPU(cpu_id);
    if (current_extended[cpu_idx]) |curr| {
        curr.time_used += 1;

        if (curr.time_used >= curr.time_quantum) {
            curr.time_used = 0;

            if (findRunnableFrom(curr.ready_next)) |next| {
                return next;
            }

            if (run_queue[cpu_idx].head) |head| {
                if (head != curr) {
                    if (findRunnableFrom(head)) |next| {
                        return next;
                    }
                }
            }
        }

        if (isRunnable(curr)) {
            return curr;
        }
    }

    return findRunnableFrom(run_queue[cpu_idx].head);
}

fn schedulePriority(cpu_id: u32) ?*ProcessExtended {
    const cpu_idx = clampCPU(cpu_id);
    var priority_level: usize = ready_queues[cpu_idx].len;

    while (priority_level > 0) {
        priority_level -= 1;
        if (findRunnableFrom(ready_queues[cpu_idx][priority_level].head)) |next| {
            return next;
        }
    }

    return null;
}

fn scheduleMLFQ(cpu_id: u32) ?*ProcessExtended {
    const cpu_idx = clampCPU(cpu_id);
    if (current_extended[cpu_idx]) |curr| {
        curr.time_used += 1;

        if (curr.time_used >= curr.time_quantum) {
            curr.time_used = 0;

            if (curr.priority != .Idle) {
                const old_priority = curr.priority;
                const new_priority: Priority = @enumFromInt(@intFromEnum(curr.priority) - 1);
                curr.priority = new_priority;
                curr.time_quantum = getQuantumForPriority(new_priority);
                moveProcessForPriorityChange(curr, old_priority, new_priority);
            }
        }

        mlfq_boost_counter[cpu_idx] += 1;
        if (mlfq_boost_counter[cpu_idx] >= MLFQ_BOOST_INTERVAL) {
            mlfq_boost_counter[cpu_idx] = 0;
            const current_ticks = timer.getTicks();
            for (&extended_processes) |*ext| {
                if (!ext.in_use or ext.assigned_cpu != cpu_id) continue;
                if (ext.base.state == .Ready) {
                    const wait_ticks = current_ticks - ext.wait_time;
                    if (wait_ticks > 100 and ext.priority != ext.original_priority) {
                        const old_priority = ext.priority;
                        const new_priority: Priority = @enumFromInt(@min(
                            @intFromEnum(ext.priority) + 1,
                            @intFromEnum(ext.original_priority),
                        ));
                        ext.priority = new_priority;
                        ext.time_quantum = getQuantumForPriority(new_priority);
                        moveProcessForPriorityChange(ext, old_priority, new_priority);
                    }
                }
            }
        }
    }

    return schedulePriority(cpu_id);
}

fn tryStealFromCPU(target_cpu: u32, source_cpu: u32) ?*ProcessExtended {
    const source_idx = clampCPU(source_cpu);

    var found: ?*ProcessExtended = null;
    if (findRunnableFrom(run_queue[source_idx].head)) |ext| {
        found = ext;
    } else {
        var priority_level: usize = ready_queues[source_idx].len;
        while (priority_level > 0 and found == null) {
            priority_level -= 1;
            found = findRunnableFrom(ready_queues[source_idx][priority_level].head);
        }
    }

    if (found) |ext| {
        dequeueFromQueue(ext);
        ext.assigned_cpu = target_cpu;
        const new_queue_index = targetQueueIndex(ext);
        if (queueForIndex(new_queue_index, target_cpu)) |queue| {
            enqueueInQueue(queue, ext, new_queue_index);
        }
        return ext;
    }

    return null;
}

fn stealRunnable(cpu_id: u32) ?*ProcessExtended {
    const cpu_count = activeCPUCount();
    if (cpu_count <= 1) return null;

    var probe: u32 = 1;
    while (probe < cpu_count) : (probe += 1) {
        const source = (cpu_id + probe) % cpu_count;
        if (tryStealFromCPU(cpu_id, source)) |stolen| {
            return stolen;
        }
    }

    return null;
}

pub fn unregisterProcess(proc: *process.Process) void {
    if (proc.extended_idx) |idx| {
        if (idx < MAX_EXTENDED_PROCESSES) {
            var ext = &extended_processes[idx];
            if (ext.in_use and ext.base == proc) {
                if (ext.queue_index != NO_QUEUE_INDEX) {
                    dequeueFromQueue(ext);
                }

                ext.in_use = false;
                for (&current_extended) |*current| {
                    if (current.* == ext) {
                        current.* = null;
                    }
                }

                if (stats.ready_processes > 0) {
                    stats.ready_processes -= 1;
                }
                if (stats.total_processes > 0) {
                    stats.total_processes -= 1;
                }
            }
        }
        proc.extended_idx = null;
    }
}

fn findExtendedProcess(base: *process.Process) ?*ProcessExtended {
    if (base.extended_idx) |idx| {
        const ext = &extended_processes[idx];
        if (ext.in_use and ext.base == base) {
            return ext;
        }
    }
    return null;
}

fn updateStatistics(cpu_id: u32) void {
    const cpu_idx = clampCPU(cpu_id);
    const total_time = idle_time[cpu_idx] + busy_time[cpu_idx];
    if (total_time > 0) {
        stats.cpu_usage_percent = @truncate((busy_time[cpu_idx] * 100) / total_time);
    }
}

pub fn getStatistics() SchedulerStats {
    return stats;
}

pub fn setProcessPriority(pid: u32, priority: Priority) bool {
    const proc = process.getProcessByPid(pid) orelse return false;
    const ext = findExtendedProcess(proc) orelse return false;

    const old_priority = ext.priority;
    ext.priority = priority;
    ext.original_priority = priority;
    ext.time_quantum = getQuantumForPriority(priority);
    moveProcessForPriorityChange(ext, old_priority, priority);
    return true;
}

pub fn setProcessNice(pid: u32, nice: i8) bool {
    const proc = process.getProcessByPid(pid) orelse return false;
    const ext = findExtendedProcess(proc) orelse return false;
    ext.nice_value = nice;

    var adjusted_priority = @intFromEnum(ext.original_priority);
    if (nice > 0) {
        adjusted_priority = @max(0, adjusted_priority - 1);
    } else if (nice < 0) {
        adjusted_priority = @min(4, adjusted_priority + 1);
    }

    const old_priority = ext.priority;
    const new_priority = @as(Priority, @enumFromInt(adjusted_priority));
    ext.priority = new_priority;
    ext.time_quantum = getQuantumForPriority(new_priority);
    moveProcessForPriorityChange(ext, old_priority, new_priority);
    return true;
}

pub fn preempt() void {
    const cpu_id = smp.getCurrentCPU();
    if (current_extended[clampCPU(cpu_id)]) |curr| {
        curr.time_used = curr.time_quantum;
    }
}

pub fn blockProcess(proc: *process.Process) void {
    const already_blocked = proc.state == .Blocked;
    proc.state = .Blocked;

    if (!already_blocked) {
        stats.blocked_processes += 1;
        if (stats.ready_processes > 0) {
            stats.ready_processes -= 1;
        }
    }

    const cpu_id = smp.getCurrentCPU();
    if (current_extended[clampCPU(cpu_id)] != null and current_extended[clampCPU(cpu_id)].?.base == proc) {
        preempt();
    }
}

pub fn unblockProcess(proc: *process.Process) void {
    const was_blocked = proc.state == .Blocked;
    proc.state = .Ready;

    if (was_blocked) {
        if (stats.blocked_processes > 0) {
            stats.blocked_processes -= 1;
        }
        stats.ready_processes += 1;
    }

    if (findExtendedProcess(proc)) |ext| {
        if (ext.queue_index == NO_QUEUE_INDEX and ext.in_use) {
            const queue_index = targetQueueIndex(ext);
            if (queueForIndex(queue_index, ext.assigned_cpu)) |queue| {
                enqueueInQueue(queue, ext, queue_index);
            }
        }
        ext.wait_time = timer.getTicks();
    }
}
