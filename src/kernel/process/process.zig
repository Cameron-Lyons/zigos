const vga = @import("../drivers/vga.zig");
const paging = @import("../memory/paging.zig");
const gdt = @import("../interrupts/gdt.zig");
const memory = @import("../memory/memory.zig");
const scheduler = @import("scheduler.zig");
const smp = @import("../smp/smp.zig");
const credentials = @import("credentials.zig");
const abi = @import("syscall/abi.zig");
const timer = @import("../timer/timer.zig");
const vfs = @import("../fs/vfs.zig");
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
    wait_next: ?*Process,
    exit_code: i32 = 0,
    page_directory: ?*paging.PageDirectory,
    entry_point: usize,
    priority: i8 = 0,
    nice_value: i8 = 0,
    time_slice: u32 = 10,
    creds: credentials.Credentials = credentials.defaultKernelCredentials(),
    parent_pid: u32 = 0,
    process_group: u32 = 0,
    alarm_time: u64 = 0,
    umask: u16 = 0o022,
    signals: signal.ProcessSignals = signal.ProcessSignals.defaultValue(),
    stdin_redirect: ?i32 = null,
    stdout_redirect: ?i32 = null,
    stderr_redirect: ?i32 = null,
    extended_idx: ?u8 = null,
};

pub export fn kernel_process_exit() callconv(.c) noreturn {
    const proc = getEffectiveCurrent() orelse {
        while (true) {
            asm volatile ("hlt");
        }
    };

    _ = terminateProcess(proc.pid);
    while (true) {
        asm volatile ("hlt");
    }
}

const MAX_PROCESSES = 256;
const SMP_MAX_CPUS = 16;
// SAFETY: all entries initialized in init() before use
pub var process_table: [MAX_PROCESSES]Process = undefined;
pub var pid_lookup: [MAX_PROCESSES]?*Process = [_]?*Process{null} ** MAX_PROCESSES;
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

    const proc = getProcessByPid(pid) orelse return false;

    cleanupStdioRedirects(proc);
    proc.state = .Terminated;
    unregisterAndRemoveProcess(proc);

    if (getEffectiveCurrent() == proc) {
        yield();
    }

    return true;
}

pub fn setPriority(pid: u32, priority: i8) bool {
    const clamped_priority = if (priority < -20) -20 else if (priority > 19) 19 else priority;

    const proc = getProcessByPid(pid) orelse return false;
    proc.priority = clamped_priority;
    proc.time_slice = @intCast(20 - @as(i32, clamped_priority));
    return true;
}

pub fn setNice(pid: u32, nice_value: i8) bool {
    const proc = getProcessByPid(pid) orelse return false;
    proc.nice_value = nice_value;
    const new_priority = proc.priority + nice_value;
    return setPriority(pid, new_priority);
}

pub fn getProcessByPid(pid: u32) ?*Process {
    if (pid == 0) return null;
    const slot = pid % MAX_PROCESSES;
    if (pid_lookup[slot]) |proc| {
        if (proc.pid == pid and proc.state != .Terminated) {
            return proc;
        }
    }
    return null;
}

pub fn unregisterAndRemoveProcess(proc: *Process) void {
    scheduler.unregisterProcess(proc);
    pid_lookup[proc.pid % MAX_PROCESSES] = null;

    var prev: ?*Process = null;
    var curr = process_list_head;
    while (curr) |p| {
        if (p == proc) {
            if (prev) |pr| {
                pr.next = p.next;
            } else {
                process_list_head = p.next;
            }
            break;
        }
        prev = p;
        curr = p.next;
    }
}

pub fn cleanupStdioRedirects(proc: *Process) void {
    const redirected = [_]*?i32{ &proc.stdin_redirect, &proc.stdout_redirect, &proc.stderr_redirect };
    for (redirected) |slot| {
        if (slot.*) |fd| {
            if (fd >= abi.FD_OFFSET) {
                const vfs_fd: u32 = @intCast(fd - abi.FD_OFFSET);
                vfs.close(vfs_fd) catch {};
            }
            slot.* = null;
        }
    }
}

pub fn adoptAsCurrent(proc: *Process) void {
    const cpu_id = smp.getCurrentCPU();
    const cpu_idx = @as(usize, @intCast(@min(cpu_id, SMP_MAX_CPUS - 1)));
    per_cpu_current[cpu_idx] = proc;
    if (cpu_idx == 0 or !smp.isSMPEnabled()) {
        current_process = proc;
    }
    scheduler.adoptCurrentProcess(proc);
}

pub fn init() void {
    vga.print("Initializing process management...\n");

    for (&process_table) |*proc| {
        proc.state = .Terminated;
        proc.pid = 0;
        proc.next = null;
        proc.wait_next = null;
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
    return create_process_internal(name, @intFromPtr(entry_point), .Kernel, .direct);
}

pub fn create_exec_process(name: []const u8) *Process {
    const proc = create_process_internal(name, @intFromPtr(&start_external_exec_process), .Kernel, .trampoline);
    proc.privilege = .User;
    proc.creds = credentials.defaultUserCredentials();
    return proc;
}

pub fn create_user_process(name: []const u8, entry_point: *const fn () void) *Process {
    return create_process_internal(name, @intFromPtr(entry_point), .User, .direct);
}

const KernelEntryMode = enum {
    direct,
    trampoline,
};

fn create_process_internal(name: []const u8, entry_point_addr: usize, privilege: ProcessPrivilege, _: KernelEntryMode) *Process {
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
    const parent = getEffectiveCurrent();
    proc.pid = next_pid;
    pid_lookup[next_pid % MAX_PROCESSES] = proc;
    next_pid += 1;
    proc.state = .Ready;

    const stack_size = 16 * 1024;
    const stack_pages = stack_size / 4096;
    proc.stack_size = stack_size;
    proc.privilege = privilege;
    proc.entry_point = entry_point_addr;

    proc.kernel_stack = memory.allocPages(stack_pages) orelse {
        vga.print("Error: Failed to allocate kernel stack!\n");
        while (true) {
            asm volatile ("hlt");
        }
    };

    if (privilege == .User) {
        proc.user_stack = memory.allocPages(stack_pages) orelse {
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
            .eip = @intCast(entry_point_addr),
            .eflags = 0x202,
            .cr3 = @intFromPtr(proc.page_directory),
            .cs = gdt.USER_CODE_SEG | 0x3,
            .ss = gdt.USER_DATA_SEG | 0x3,
        };
    } else {
        const kernel_stack_top = @intFromPtr(proc.kernel_stack + stack_size);
        var frame = kernel_stack_top;
        frame -= @sizeOf(usize);
        @as(*usize, @ptrFromInt(frame)).* = @intFromPtr(&kernel_process_exit);
        frame -= @sizeOf(usize);
        @as(*usize, @ptrFromInt(frame)).* = entry_point_addr;
        frame -= @sizeOf(usize);
        @as(*usize, @ptrFromInt(frame)).* = 0x2;
        frame -= @sizeOf(usize);
        @as(*usize, @ptrFromInt(frame)).* = 0;
        frame -= @sizeOf(usize);
        @as(*usize, @ptrFromInt(frame)).* = 0;
        frame -= @sizeOf(usize);
        @as(*usize, @ptrFromInt(frame)).* = 0;
        frame -= @sizeOf(usize);
        @as(*usize, @ptrFromInt(frame)).* = 0;
        frame -= @sizeOf(usize);
        @as(*usize, @ptrFromInt(frame)).* = 0;
        frame -= @sizeOf(usize);
        @as(*usize, @ptrFromInt(frame)).* = 0;
        frame -= @sizeOf(usize);
        @as(*usize, @ptrFromInt(frame)).* = 0;
        proc.context = Context{
            .eax = 0,
            .ebx = 0,
            .ecx = 0,
            .edx = 0,
            .esi = 0,
            .edi = 0,
            .ebp = 0,
            .esp = frame,
            .eip = @intFromPtr(&resume_process),
            .eflags = 0x202,
            .cr3 = 0,
            .cs = gdt.KERNEL_CODE_SEG,
            .ss = gdt.KERNEL_DATA_SEG,
        };
    }

    proc.creds = if (privilege == .Kernel) credentials.defaultKernelCredentials() else credentials.defaultUserCredentials();
    proc.parent_pid = if (parent) |p| p.pid else 0;
    proc.process_group = if (parent) |p|
        if (p.process_group != 0) p.process_group else p.pid
    else
        proc.pid;

    @memset(&proc.name, 0);
    const copy_len = @min(name.len, proc.name.len - 1);
    @memcpy(proc.name[0..copy_len], name[0..copy_len]);

    proc.next = process_list_head;
    proc.wait_next = null;
    process_list_head = proc;

    const priority = if (privilege == .Kernel) scheduler.Priority.High else scheduler.Priority.Normal;
    _ = scheduler.registerProcess(proc, priority);
    if (parent != null) {
        scheduler.assignProcessToCPU(proc, smp.getCurrentCPU());
    }

    vga.print("Created process: ");
    vga.print(name);
    vga.print(" (PID: ");
    print_number(proc.pid);
    vga.print(")\n");

    return proc;
}

pub fn schedule() ?*Process {
    return scheduler.scheduleForCPU(smp.getCurrentCPU());
}

extern fn context_switch(old: *Context, new: *Context) void;
extern fn resume_process() noreturn;
extern fn start_external_exec_process() void;
extern fn jump_to_context_struct(ctx: *Context) noreturn;
extern fn switch_to_user_mode(entry_point: u32, user_stack: u32) void;
extern fn task_switch() void;
extern fn save_process_state(ctx: *Context) void;
extern fn restore_process_state(ctx: *Context) void;

pub fn switch_process(old: *Context, new: *Context) void {
    if (getEffectiveCurrent()) |curr| {
        if ((curr.context.cs & 0x3) == 0x3) {
            const kernel_stack_top = @intFromPtr(curr.kernel_stack) + curr.stack_size;
            gdt.setKernelStack(kernel_stack_top);
        }
    }

    context_switch(old, new);
}

fn markScheduledProcesses(old_proc: *Process, new_proc: *Process) void {
    if (old_proc != new_proc and old_proc.state == .Running) {
        old_proc.state = .Ready;
    }

    new_proc.state = .Running;
}

pub fn yield() void {
    const cpu_id = smp.getCurrentCPU();
    smp.scheduler_lock.acquire();
    scheduler.preempt();
    const next = scheduler.scheduleForCPU(cpu_id);
    const cpu_idx = @as(usize, @intCast(@min(cpu_id, SMP_MAX_CPUS - 1)));
    const old_proc = if (smp.isSMPEnabled() and cpu_idx < SMP_MAX_CPUS)
        per_cpu_current[cpu_idx] orelse current_process
    else
        current_process;

    if (next != null and old_proc != null and next != old_proc) {
        const old = old_proc.?;
        const new = next.?;
        if (smp.isSMPEnabled() and cpu_idx < SMP_MAX_CPUS) {
            per_cpu_current[cpu_idx] = new;
        }
        if (cpu_idx == 0 or !smp.isSMPEnabled()) {
            current_process = new;
        }
        markScheduledProcesses(old, new);
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
    return getEffectiveCurrent();
}

pub fn getCurrentPID() u32 {
    if (getEffectiveCurrent()) |proc| {
        return proc.pid;
    }
    return 0;
}

pub fn getSystemTime() u64 {
    return timer.getTicks();
}

pub export fn switchToProcess(proc: *Process) noreturn {
    if (getEffectiveCurrent()) |old_proc| {
        markScheduledProcesses(old_proc, proc);
    } else {
        proc.state = .Running;
    }

    const cpu_id = smp.getCurrentCPU();
    const cpu_idx = @as(usize, @intCast(@min(cpu_id, SMP_MAX_CPUS - 1)));
    per_cpu_current[cpu_idx] = proc;
    if (cpu_idx == 0 or !smp.isSMPEnabled()) {
        current_process = proc;
    }
    scheduler.adoptCurrentProcess(proc);

    if (proc.page_directory) |pd| {
        paging.switchPageDirectory(pd);
    } else {
        paging.switchPageDirectory(paging.getKernelPageDirectory());
    }

    const kernel_stack_top = @intFromPtr(proc.kernel_stack) + proc.stack_size;
    gdt.setKernelStack(kernel_stack_top);

    if ((proc.context.cs & 0x3) == 0x3) {
        switch_to_user_mode(proc.context.eip, proc.context.esp);
    } else {
        jump_to_context_struct(&proc.context);
    }

    unreachable;
}
