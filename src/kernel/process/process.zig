const vga = @import("../drivers/vga.zig");
const paging = @import("../memory/paging.zig");
const gdt = @import("../interrupts/gdt.zig");
const memory = @import("../memory/memory.zig");
const scheduler = @import("scheduler.zig");
const smp = @import("../smp/smp.zig");
const credentials = @import("credentials.zig");
const timer = @import("../timer/timer.zig");
pub const signal = @import("signal.zig");

pub const ProcessState = enum {
    Ready,
    Running,
    Blocked,
    Terminated,
    Zombie,
    Stopped,
    Waiting,
};

pub const ProcessPrivilege = enum {
    Kernel,
    User,
};

pub const Context = struct {
    eax: u32,
    ebx: u32,
    ecx: u32,
    edx: u32,
    esi: u32,
    edi: u32,
    ebp: u32,
    esp: u32,
    eip: u32,
    eflags: u32,
    cr3: u32,
    cs: u32,
    ss: u32,
};

pub const Process = struct {
    pid: u32,
    state: ProcessState,
    privilege: ProcessPrivilege,
    context: Context,
    kernel_stack: [*]u8,
    user_stack: [*]u8,
    stack_size: u32,
    name: [64]u8,
    next: ?*Process,
    exit_code: i32 = 0,
    page_directory: ?*paging.PageDirectory,
    entry_point: *const fn () void,
    priority: i8 = 0,
    nice_value: i8 = 0,
    time_slice: u32 = 10,
    creds: credentials.Credentials = credentials.defaultKernelCredentials(),
    parent_pid: u32 = 0,
    process_group: u32 = 0,
    alarm_time: u64 = 0,
    signals: signal.ProcessSignals = signal.ProcessSignals.defaultValue(),
};

const MAX_PROCESSES = 256;
const SMP_MAX_CPUS = 16;
// SAFETY: all entries initialized in init() before use
pub var process_table: [MAX_PROCESSES]Process = undefined;
pub var next_pid: u32 = 1;
pub var current_process: ?*Process = null;
pub var process_list_head: ?*Process = null;
// SAFETY: Initialized in initScheduler() before use
var idle_process: *Process = undefined;
var per_cpu_current: [SMP_MAX_CPUS]?*Process = [_]?*Process{null} ** SMP_MAX_CPUS;

pub fn setPerCPUCurrent(cpu_id: u32, proc: *Process) void {
    if (cpu_id < SMP_MAX_CPUS) {
        per_cpu_current[cpu_id] = proc;
    }
}

pub fn getEffectiveCurrent() ?*Process {
    if (smp.isSMPEnabled()) {
        const cpu_id = smp.getCurrentCPU();
        if (cpu_id < SMP_MAX_CPUS and per_cpu_current[cpu_id] != null) {
            return per_cpu_current[cpu_id];
        }
    }
    return current_process;
}

pub fn getProcessList() ?*Process {
    return process_list_head;
}

pub fn terminateProcess(pid: u32) bool {
    if (pid == 0) return false;

    var i: usize = 0;
    while (i < MAX_PROCESSES) : (i += 1) {
        if (process_table[i].pid == pid and process_table[i].state != .Terminated) {
            process_table[i].state = .Terminated;

            var prev: ?*Process = null;
            var curr = process_list_head;
            while (curr) |proc| {
                if (proc == &process_table[i]) {
                    if (prev) |p| {
                        p.next = proc.next;
                    } else {
                        process_list_head = proc.next;
                    }
                    break;
                }
                prev = proc;
                curr = proc.next;
            }

            if (current_process == &process_table[i]) {
                yield();
            }

            return true;
        }
    }
    return false;
}

pub fn setPriority(pid: u32, priority: i8) bool {

    const clamped_priority = if (priority < -20) -20 else if (priority > 19) 19 else priority;

    var i: usize = 0;
    while (i < MAX_PROCESSES) : (i += 1) {
        if (process_table[i].pid == pid and process_table[i].state != .Terminated) {
            process_table[i].priority = clamped_priority;

            process_table[i].time_slice = @intCast(20 - @as(i32, clamped_priority));
            return true;
        }
    }
    return false;
}

pub fn setNice(pid: u32, nice_value: i8) bool {

    var i: usize = 0;
    while (i < MAX_PROCESSES) : (i += 1) {
        if (process_table[i].pid == pid and process_table[i].state != .Terminated) {
            process_table[i].nice_value = nice_value;

            const new_priority = process_table[i].priority + nice_value;
            return setPriority(pid, new_priority);
        }
    }
    return false;
}

pub fn getProcess(pid: u32) ?*Process {
    return getProcessByPid(pid);
}

pub fn getProcessByPid(pid: u32) ?*Process {
    var i: usize = 0;
    while (i < MAX_PROCESSES) : (i += 1) {
        if (process_table[i].pid == pid and process_table[i].state != .Terminated) {
            return &process_table[i];
        }
    }
    return null;
}

pub fn init() void {
    vga.print("Initializing process management...\n");

    for (&process_table) |*proc| {
        proc.state = .Terminated;
        proc.pid = 0;
        proc.next = null;
    }

    scheduler.init();

    idle_process = create_kernel_process("idle", idle_task);
    current_process = idle_process;
    per_cpu_current[0] = idle_process;

    vga.print("Process management initialized!\n");
}

fn idle_task() void {
    while (true) {
        asm volatile ("hlt");
    }
}

pub fn create_process(name: []const u8, entry_point: *const fn () void) *Process {
    return create_kernel_process(name, entry_point);
}

pub fn create_kernel_process(name: []const u8, entry_point: *const fn () void) *Process {
    return create_process_internal(name, entry_point, .Kernel);
}

pub fn create_user_process(name: []const u8, entry_point: *const fn () void) *Process {
    return create_process_internal(name, entry_point, .User);
}

fn create_process_internal(name: []const u8, entry_point: *const fn () void, privilege: ProcessPrivilege) *Process {
    var process: ?*Process = null;

    for (&process_table) |*proc| {
        if (proc.state == .Terminated) {
            process = proc;
            break;
        }
    }

    if (process == null) {
        vga.print("Error: No free process slots!\n");
        while (true) {
            asm volatile ("hlt");
        }
    }

    const proc = process.?;
    proc.pid = next_pid;
    next_pid += 1;
    proc.state = .Ready;

    const stack_size = 4096;
    proc.stack_size = stack_size;
    proc.privilege = privilege;
    proc.entry_point = entry_point;

    proc.kernel_stack = memory.allocPages(1) orelse {
        vga.print("Error: Failed to allocate kernel stack!\n");
        while (true) {
            asm volatile ("hlt");
        }
    };

    if (privilege == .User) {
        proc.user_stack = memory.allocPages(1) orelse {
            vga.print("Error: Failed to allocate user stack!\n");
            while (true) {
                asm volatile ("hlt");
            }
        };

        proc.page_directory = paging.createUserPageDirectory() catch {
            vga.print("Error: Failed to create user page directory!\n");
            while (true) {
                asm volatile ("hlt");
            }
        };
    } else {
        proc.user_stack = proc.kernel_stack;
        proc.page_directory = null;
    }

    if (privilege == .User) {
        proc.context = Context{
            .eax = 0,
            .ebx = 0,
            .ecx = 0,
            .edx = 0,
            .esi = 0,
            .edi = 0,
            .ebp = @intFromPtr(proc.user_stack + stack_size),
            .esp = @intFromPtr(proc.user_stack + stack_size - 8),
            .eip = @intFromPtr(entry_point),
            .eflags = 0x202,
            .cr3 = @intFromPtr(proc.page_directory),
            .cs = gdt.USER_CODE_SEG | 0x3,
            .ss = gdt.USER_DATA_SEG | 0x3,
        };
    } else {
        proc.context = Context{
            .eax = 0,
            .ebx = 0,
            .ecx = 0,
            .edx = 0,
            .esi = 0,
            .edi = 0,
            .ebp = @intFromPtr(proc.kernel_stack + stack_size),
            .esp = @intFromPtr(proc.kernel_stack + stack_size - 8),
            .eip = @intFromPtr(entry_point),
            .eflags = 0x202,
            .cr3 = 0,
            .cs = gdt.KERNEL_CODE_SEG,
            .ss = gdt.KERNEL_DATA_SEG,
        };
    }

    proc.creds = if (privilege == .Kernel) credentials.defaultKernelCredentials() else credentials.defaultUserCredentials();

    @memset(&proc.name, 0);
    const copy_len = @min(name.len, proc.name.len - 1);
    @memcpy(proc.name[0..copy_len], name[0..copy_len]);

    proc.next = process_list_head;
    process_list_head = proc;

    const priority = if (privilege == .Kernel) scheduler.Priority.High else scheduler.Priority.Normal;
    _ = scheduler.registerProcess(proc, priority);

    vga.print("Created process: ");
    vga.print(name);
    vga.print(" (PID: ");
    print_number(proc.pid);
    vga.print(")\n");

    return proc;
}

pub fn schedule() ?*Process {
    return scheduler.schedule();
}

extern fn context_switch(old: *Context, new: *Context) void;
extern fn switch_to_user_mode(entry_point: u32, user_stack: u32) void;
extern fn task_switch() void;
extern fn save_process_state(ctx: *Context) void;
extern fn restore_process_state(ctx: *Context) void;

pub fn switch_process(old: *Context, new: *Context) void {

    if (current_process != null and current_process.?.privilege == .User) {
        const kernel_stack_top = @intFromPtr(current_process.?.kernel_stack) + current_process.?.stack_size;
        gdt.setKernelStack(kernel_stack_top);
    }

    context_switch(old, new);
}

pub fn yield() void {
    smp.scheduler_lock.acquire();
    const next = schedule();
    const cpu_id = smp.getCurrentCPU();
    const old_proc = if (smp.isSMPEnabled() and cpu_id < SMP_MAX_CPUS)
        per_cpu_current[cpu_id] orelse current_process
    else
        current_process;

    if (next != null and old_proc != null and next != old_proc) {
        const old = old_proc.?;
        const new = next.?;
        if (smp.isSMPEnabled() and cpu_id < SMP_MAX_CPUS) {
            per_cpu_current[cpu_id] = new;
        }
        current_process = new;
        old.state = .Ready;
        new.state = .Running;
        smp.scheduler_lock.release();
        switch_process(&old.context, &new.context);
    } else {
        smp.scheduler_lock.release();
    }
}

fn print_number(num: u32) void {
    if (num == 0) {
        vga.put_char('0');
        return;
    }

    // SAFETY: filled by the following digit extraction loop
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

pub export fn getCurrentProcess() ?*Process {
    return current_process;
}

pub fn getCurrentPID() u32 {
    if (current_process) |proc| {
        return proc.pid;
    }
    return 0;
}

pub fn getSystemTime() u64 {
    return timer.getTicks();
}

pub export fn switchToProcess(proc: *Process) void {
    if (current_process) |old_proc| {
        old_proc.state = .Ready;
    }

    current_process = proc;
    proc.state = .Running;

    if (proc.page_directory) |pd| {
        paging.switchPageDirectory(pd);
    }

    const kernel_stack_top = @intFromPtr(proc.kernel_stack) + proc.stack_size;
    gdt.setKernelStack(kernel_stack_top);

    if (proc.privilege == .User) {
        switch_to_user_mode(proc.context.eip, proc.context.esp);
    } else {
        asm volatile (
            \\mov %[esp], %%esp
            \\mov %[ebp], %%ebp
            \\jmp *%[eip]
            :
            : [esp] "r" (proc.context.esp),
              [ebp] "r" (proc.context.ebp),
              [eip] "r" (proc.context.eip),
        );
    }
}
