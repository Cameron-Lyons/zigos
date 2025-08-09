const std = @import("std");
const vga = @import("vga.zig");
const process = @import("process.zig");
const timer = @import("timer.zig");

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
    in_use: bool,
};

const MAX_EXTENDED_PROCESSES = 256;
var extended_processes: [MAX_EXTENDED_PROCESSES]ProcessExtended = undefined;
var scheduler_type: SchedulerType = .RoundRobin;
var stats: SchedulerStats = .{
    .context_switches = 0,
    .total_processes = 0,
    .ready_processes = 0,
    .blocked_processes = 0,
    .cpu_usage_percent = 0,
};

var current_extended: ?*ProcessExtended = null;
var ready_queues: [5]?*ProcessExtended = .{ null, null, null, null, null };
var run_queue_head: ?*ProcessExtended = null;
var idle_time: u64 = 0;
var busy_time: u64 = 0;

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
    }
    
    scheduler_type = .RoundRobin;
    vga.print("Scheduler initialized with Round Robin algorithm\n");
}

pub fn setSchedulerType(sched_type: SchedulerType) void {
    scheduler_type = sched_type;
    vga.print("Scheduler changed to: ");
    switch (sched_type) {
        .RoundRobin => vga.print("Round Robin"),
        .Priority => vga.print("Priority"),
        .MultiLevelFeedback => vga.print("Multi-Level Feedback Queue"),
    }
    vga.print("\n");
}

pub fn registerProcess(proc: *process.Process, priority: Priority) *ProcessExtended {
    for (&extended_processes) |*ext| {
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
            ext.in_use = true;
            
            addToReadyQueue(ext);
            stats.total_processes += 1;
            
            return ext;
        }
    }
    
    vga.print("Warning: No space for extended process info\n");
    return &extended_processes[0];
}

fn getQuantumForPriority(priority: Priority) u32 {
    for (QUANTUM_TABLE) |quantum| {
        if (quantum.priority == priority) {
            return quantum.ticks;
        }
    }
    return 10;
}

fn addToReadyQueue(new_ext: *ProcessExtended) void {
    const priority_index = @intFromEnum(new_ext.priority);
    new_ext.base.state = .Ready;
    
    if (scheduler_type == .Priority or scheduler_type == .MultiLevelFeedback) {
        var current = ready_queues[priority_index];
        if (current == null) {
            ready_queues[priority_index] = new_ext;
        } else {
            while (current.?.base.next != null) {
                const next_proc = current.?.base.next.?;
                current = findExtendedProcess(next_proc);
                if (current == null) break;
            }
            if (current != null) {
                current.?.base.next = new_ext.base;
            }
        }
    } else {
        if (run_queue_head == null) {
            run_queue_head = new_ext;
            new_ext.base.next = null;
        } else {
            var current = run_queue_head;
            while (current.?.base.next != null) {
                const next_proc = current.?.base.next.?;
                current = findExtendedProcess(next_proc);
                if (current == null) break;
            }
            if (current != null) {
                current.?.base.next = new_ext.base;
            }
        }
    }
    
    stats.ready_processes += 1;
}

pub fn schedule() ?*process.Process {
    updateStatistics();
    
    const next = switch (scheduler_type) {
        .RoundRobin => scheduleRoundRobin(),
        .Priority => schedulePriority(),
        .MultiLevelFeedback => scheduleMLFQ(),
    };
    
    if (next) |ext| {
        if (current_extended != ext) {
            stats.context_switches += 1;
            
            if (current_extended) |curr| {
                curr.time_used = 0;
                curr.wait_time = timer.getTicks();
            }
            
            ext.last_scheduled = timer.getTicks();
            if (ext.response_time == 0) {
                ext.response_time = timer.getTicks();
            }
            
            current_extended = ext;
        }
        
        return ext.base;
    }
    
    idle_time += 1;
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

fn scheduleRoundRobin() ?*ProcessExtended {
    if (current_extended) |curr| {
        curr.time_used += 1;
        
        if (curr.time_used >= curr.time_quantum) {
            curr.time_used = 0;
            
            if (curr.base.next) |next_base| {
                const next_ext = findExtendedProcess(next_base);
                if (next_ext != null and next_ext.?.base.state == .Ready) {
                    return next_ext;
                }
            }
            
            if (run_queue_head) |head| {
                if (head.base.state == .Ready) {
                    return head;
                }
            }
        }
        
        if (curr.base.state == .Ready or curr.base.state == .Running) {
            return curr;
        }
    }
    
    if (run_queue_head) |head| {
        var current = head;
        while (current.base.state != .Ready) {
            if (current.base.next) |next_base| {
                current = findExtendedProcess(next_base) orelse return null;
            } else {
                break;
            }
        }
        
        if (current.base.state == .Ready) {
            return current;
        }
    }
    
    return null;
}

fn schedulePriority() ?*ProcessExtended {
    var priority_index: usize = @intFromEnum(Priority.RealTime);
    
    while (priority_index > 0) : (priority_index -= 1) {
        if (ready_queues[priority_index]) |queue_head| {
            var current = queue_head;
            while (current.base.state != .Ready) {
                if (current.base.next) |next_base| {
                    current = findExtendedProcess(next_base) orelse break;
                } else {
                    break;
                }
            }
            
            if (current.base.state == .Ready) {
                return current;
            }
        }
    }
    
    return null;
}

fn scheduleMLFQ() ?*ProcessExtended {
    if (current_extended) |curr| {
        curr.time_used += 1;
        
        if (curr.time_used >= curr.time_quantum) {
            curr.time_used = 0;
            
            if (curr.priority != .Idle) {
                const new_priority = @as(Priority, @enumFromInt(@intFromEnum(curr.priority) - 1));
                curr.priority = new_priority;
                curr.time_quantum = getQuantumForPriority(new_priority);
            }
        }
        
        const current_ticks = timer.getTicks();
        for (&extended_processes) |*ext| {
            if (ext.in_use and ext.base.state == .Ready) {
                const wait_ticks = current_ticks - ext.wait_time;
                if (wait_ticks > 100 and ext.priority != ext.original_priority) {
                    const new_priority = @as(Priority, @enumFromInt(@min(
                        @intFromEnum(ext.priority) + 1,
                        @intFromEnum(ext.original_priority)
                    )));
                    ext.priority = new_priority;
                    ext.time_quantum = getQuantumForPriority(new_priority);
                }
            }
        }
    }
    
    return schedulePriority();
}

fn findExtendedProcess(base: *process.Process) ?*ProcessExtended {
    for (&extended_processes) |*ext| {
        if (ext.in_use and ext.base == base) {
            return ext;
        }
    }
    return null;
}

fn updateStatistics() void {
    stats.ready_processes = 0;
    stats.blocked_processes = 0;
    
    for (&extended_processes) |*ext| {
        if (ext.in_use) {
            switch (ext.base.state) {
                .Ready => stats.ready_processes += 1,
                .Blocked => stats.blocked_processes += 1,
                else => {},
            }
        }
    }
    
    const total_time = idle_time + busy_time;
    if (total_time > 0) {
        stats.cpu_usage_percent = @truncate((busy_time * 100) / total_time);
    }
}

pub fn getStatistics() SchedulerStats {
    return stats;
}

pub fn setProcessPriority(pid: u32, priority: Priority) bool {
    for (&extended_processes) |*ext| {
        if (ext.in_use and ext.base.pid == pid) {
            ext.priority = priority;
            ext.original_priority = priority;
            ext.time_quantum = getQuantumForPriority(priority);
            return true;
        }
    }
    return false;
}

pub fn setProcessNice(pid: u32, nice: i8) bool {
    for (&extended_processes) |*ext| {
        if (ext.in_use and ext.base.pid == pid) {
            ext.nice_value = nice;
            
            var adjusted_priority = @intFromEnum(ext.original_priority);
            if (nice > 0) {
                adjusted_priority = @max(0, adjusted_priority - 1);
            } else if (nice < 0) {
                adjusted_priority = @min(4, adjusted_priority + 1);
            }
            
            ext.priority = @as(Priority, @enumFromInt(adjusted_priority));
            ext.time_quantum = getQuantumForPriority(ext.priority);
            return true;
        }
    }
    return false;
}

pub fn preempt() void {
    if (current_extended) |curr| {
        curr.time_used = curr.time_quantum;
    }
}

pub fn blockProcess(proc: *process.Process) void {
    proc.state = .Blocked;
    stats.blocked_processes += 1;
    stats.ready_processes -= 1;
    
    if (current_extended != null and current_extended.?.base == proc) {
        preempt();
    }
}

pub fn unblockProcess(proc: *process.Process) void {
    proc.state = .Ready;
    stats.blocked_processes -= 1;
    stats.ready_processes += 1;
    
    if (findExtendedProcess(proc)) |ext| {
        ext.wait_time = timer.getTicks();
    }
}