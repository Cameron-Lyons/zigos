const std = @import("std");
const vga = @import("../drivers/vga.zig");
const process = @import("../process/process.zig");
const scheduler = @import("../process/scheduler.zig");
const timer = @import("../timer/timer.zig");
const memory = @import("../memory/memory.zig");
const paging = @import("../memory/paging.zig");

pub const ProcessStats = struct {
    pid: u32,
    name: [64]u8,
    state: process.ProcessState,
    priority: scheduler.Priority,
    cpu_time: u64,
    memory_usage: u32,
    page_faults: u32,
    context_switches: u32,
    start_time: u64,
    parent_pid: u32,
    child_count: u32,
    thread_count: u32,
};

pub const SystemStats = struct {
    total_processes: u32,
    running_processes: u32,
    ready_processes: u32,
    blocked_processes: u32,
    terminated_processes: u32,
    total_cpu_time: u64,
    idle_time: u64,
    context_switches: u64,
    interrupts_handled: u64,
    system_calls: u64,
    page_faults: u64,
    memory_total: u32,
    memory_used: u32,
    memory_free: u32,
    uptime_ticks: u64,
};

pub const CPUUsage = struct {
    user_percent: u32,
    system_percent: u32,
    idle_percent: u32,
    iowait_percent: u32,
};

const MAX_TRACKED_PROCESSES = 256;
var process_stats: [MAX_TRACKED_PROCESSES]ProcessStats = undefined;
var system_stats: SystemStats = undefined;
var cpu_usage: CPUUsage = undefined;

var last_update_time: u64 = 0;
var update_interval: u64 = 100;

var cpu_samples: [100]CPUUsage = undefined;
var sample_index: usize = 0;

pub fn init() void {
    vga.print("Initializing process monitoring...\n");

    system_stats = SystemStats{
        .total_processes = 0,
        .running_processes = 0,
        .ready_processes = 0,
        .blocked_processes = 0,
        .terminated_processes = 0,
        .total_cpu_time = 0,
        .idle_time = 0,
        .context_switches = 0,
        .interrupts_handled = 0,
        .system_calls = 0,
        .page_faults = 0,
        .memory_total = 0,
        .memory_used = 0,
        .memory_free = 0,
        .uptime_ticks = 0,
    };

    cpu_usage = CPUUsage{
        .user_percent = 0,
        .system_percent = 0,
        .idle_percent = 100,
        .iowait_percent = 0,
    };

    for (&process_stats) |*stat| {
        stat.pid = 0;
        stat.cpu_time = 0;
        stat.memory_usage = 0;
        stat.page_faults = 0;
        stat.context_switches = 0;
        stat.start_time = 0;
        stat.parent_pid = 0;
        stat.child_count = 0;
        stat.thread_count = 1;
    }

    last_update_time = timer.getTicks();

    vga.print("Process monitoring initialized\n");
}

pub fn updateStats() void {
    const current_time = timer.getTicks();

    if (current_time - last_update_time < update_interval) {
        return;
    }

    last_update_time = current_time;
    system_stats.uptime_ticks = current_time;

    const sched_stats = scheduler.getStatistics();
    system_stats.context_switches = sched_stats.context_switches;
    system_stats.total_processes = sched_stats.total_processes;
    system_stats.ready_processes = sched_stats.ready_processes;
    system_stats.blocked_processes = sched_stats.blocked_processes;

    const mem_stats = paging.getMemoryStats();
    system_stats.memory_total = mem_stats.total_frames * 4096;
    system_stats.memory_used = mem_stats.used_frames * 4096;
    system_stats.memory_free = (mem_stats.total_frames - mem_stats.used_frames) * 4096;

    system_stats.running_processes = 0;
    system_stats.terminated_processes = 0;

    var proc = process.getProcessList();
    var proc_index: usize = 0;

    while (proc) |p| : (proc = p.next) {
        if (proc_index < MAX_TRACKED_PROCESSES) {
            process_stats[proc_index].pid = p.pid;
            @memcpy(&process_stats[proc_index].name, &p.name);
            process_stats[proc_index].state = p.state;

            switch (p.state) {
                .Running => system_stats.running_processes += 1,
                .Terminated => system_stats.terminated_processes += 1,
                else => {},
            }

            proc_index += 1;
        }
    }

    updateCPUUsage();
}

fn updateCPUUsage() void {
    const total_time = system_stats.total_cpu_time + system_stats.idle_time;

    if (total_time == 0) {
        cpu_usage.user_percent = 0;
        cpu_usage.system_percent = 0;
        cpu_usage.idle_percent = 100;
        cpu_usage.iowait_percent = 0;
    } else {
        const cpu_percent = (system_stats.total_cpu_time * 100) / total_time;
        cpu_usage.user_percent = @truncate(cpu_percent * 70 / 100);
        cpu_usage.system_percent = @truncate(cpu_percent * 30 / 100);
        cpu_usage.idle_percent = @truncate((system_stats.idle_time * 100) / total_time);
        cpu_usage.iowait_percent = 0;
    }

    cpu_samples[sample_index] = cpu_usage;
    sample_index = (sample_index + 1) % cpu_samples.len;
}

pub fn getProcessStats(pid: u32) ?ProcessStats {
    for (process_stats) |stat| {
        if (stat.pid == pid) {
            return stat;
        }
    }
    return null;
}

pub fn getSystemStats() SystemStats {
    updateStats();
    return system_stats;
}

pub fn getCPUUsage() CPUUsage {
    return cpu_usage;
}

pub fn getAverageCPUUsage() CPUUsage {
    var avg = CPUUsage{
        .user_percent = 0,
        .system_percent = 0,
        .idle_percent = 0,
        .iowait_percent = 0,
    };

    var count: u32 = 0;
    for (cpu_samples) |sample| {
        if (sample.user_percent > 0 or sample.system_percent > 0 or sample.idle_percent > 0) {
            avg.user_percent += sample.user_percent;
            avg.system_percent += sample.system_percent;
            avg.idle_percent += sample.idle_percent;
            avg.iowait_percent += sample.iowait_percent;
            count += 1;
        }
    }

    if (count > 0) {
        avg.user_percent /= count;
        avg.system_percent /= count;
        avg.idle_percent /= count;
        avg.iowait_percent /= count;
    } else {
        avg.idle_percent = 100;
    }

    return avg;
}

pub fn printProcessList() void {
    updateStats();

    vga.print("\nProcess List:\n");
    vga.print("PID   NAME                STATE      PRIORITY   CPU_TIME\n");
    vga.print("----  ----------------    ---------  ---------  --------\n");

    for (process_stats) |stat| {
        if (stat.pid == 0) continue;

        print_number_width(stat.pid, 4);
        vga.print("  ");

        var name_len: usize = 0;
        while (name_len < 64 and stat.name[name_len] != 0) : (name_len += 1) {}

        var i: usize = 0;
        while (i < @min(name_len, 20)) : (i += 1) {
            vga.put_char(stat.name[i]);
        }
        while (i < 20) : (i += 1) {
            vga.put_char(' ');
        }

        switch (stat.state) {
            .Running => vga.print("RUNNING   "),
            .Ready => vga.print("READY     "),
            .Blocked => vga.print("BLOCKED   "),
            .Terminated => vga.print("TERMINATED"),
        }
        vga.print("  ");

        print_number_width(@as(u32, @truncate(stat.cpu_time)), 8);
        vga.print("\n");
    }
}

pub fn printSystemStats() void {
    updateStats();

    vga.print("\n=== System Statistics ===\n");

    vga.print("Processes:\n");
    vga.print("  Total:      ");
    print_number(system_stats.total_processes);
    vga.print("\n  Running:    ");
    print_number(system_stats.running_processes);
    vga.print("\n  Ready:      ");
    print_number(system_stats.ready_processes);
    vga.print("\n  Blocked:    ");
    print_number(system_stats.blocked_processes);
    vga.print("\n  Terminated: ");
    print_number(system_stats.terminated_processes);
    vga.print("\n\n");

    vga.print("CPU Usage:\n");
    vga.print("  User:   ");
    print_number(cpu_usage.user_percent);
    vga.print("%\n  System: ");
    print_number(cpu_usage.system_percent);
    vga.print("%\n  Idle:   ");
    print_number(cpu_usage.idle_percent);
    vga.print("%\n\n");

    vga.print("Memory:\n");
    vga.print("  Total: ");
    print_number(system_stats.memory_total / 1024);
    vga.print(" KB\n  Used:  ");
    print_number(system_stats.memory_used / 1024);
    vga.print(" KB\n  Free:  ");
    print_number(system_stats.memory_free / 1024);
    vga.print(" KB\n\n");

    vga.print("Performance:\n");
    vga.print("  Context Switches: ");
    print_number(@truncate(system_stats.context_switches));
    vga.print("\n  Page Faults:      ");
    print_number(@truncate(system_stats.page_faults));
    vga.print("\n  System Calls:     ");
    print_number(@truncate(system_stats.system_calls));
    vga.print("\n\n");

    const uptime_seconds = system_stats.uptime_ticks / 100;
    const hours = uptime_seconds / 3600;
    const minutes = (uptime_seconds % 3600) / 60;
    const seconds = uptime_seconds % 60;

    vga.print("Uptime: ");
    print_number(@truncate(hours));
    vga.print("h ");
    print_number(@truncate(minutes));
    vga.print("m ");
    print_number(@truncate(seconds));
    vga.print("s\n");
}

pub fn printCPUGraph() void {
    vga.print("\nCPU Usage History:\n");

    const graph_height = 10;
    const graph_width = 50;

    var row: usize = graph_height;
    while (row > 0) : (row -= 1) {
        const threshold = row * 10;

        if (row == graph_height) {
            vga.print("100% |");
        } else if (row == graph_height / 2) {
            vga.print(" 50% |");
        } else if (row == 1) {
            vga.print("  0% |");
        } else {
            vga.print("     |");
        }

        var col: usize = 0;
        while (col < @min(graph_width, sample_index)) : (col += 1) {
            const usage = 100 - cpu_samples[col].idle_percent;
            if (usage >= threshold) {
                vga.put_char('#');
            } else {
                vga.put_char(' ');
            }
        }

        vga.print("\n");
    }

    vga.print("     +");
    var i: usize = 0;
    while (i < graph_width) : (i += 1) {
        vga.put_char('-');
    }
    vga.print("\n");
}

pub fn recordProcessEvent(pid: u32, event_type: ProcessEventType) void {
    _ = pid;

    switch (event_type) {
        .ContextSwitch => system_stats.context_switches += 1,
        .PageFault => system_stats.page_faults += 1,
        .SystemCall => system_stats.system_calls += 1,
        .Interrupt => system_stats.interrupts_handled += 1,
    }
}

pub const ProcessEventType = enum {
    ContextSwitch,
    PageFault,
    SystemCall,
    Interrupt,
};

fn print_number(num: u32) void {
    if (num == 0) {
        vga.put_char('0');
        return;
    }

    var digits: [10]u8 = undefined;
    var i: usize = 0;
    var n = num;

    while (n > 0) : (n /= 10) {
        digits[i] = @as(u8, @truncate(n % 10)) + '0';
        i += 1;
    }

    while (i > 0) {
        i -= 1;
        vga.put_char(digits[i]);
    }
}

fn print_number_width(num: u32, width: usize) void {
    var digits: [10]u8 = undefined;
    var digit_count: usize = 0;
    var n = num;

    if (n == 0) {
        digits[0] = '0';
        digit_count = 1;
    } else {
        while (n > 0) : (n /= 10) {
            digits[digit_count] = @as(u8, @truncate(n % 10)) + '0';
            digit_count += 1;
        }
    }

    var padding = width;
    if (digit_count < width) {
        padding = width - digit_count;
    } else {
        padding = 0;
    }

    while (padding > 0) : (padding -= 1) {
        vga.put_char(' ');
    }

    var i = digit_count;
    while (i > 0) {
        i -= 1;
        vga.put_char(digits[i]);
    }
}