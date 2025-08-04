const std = @import("std");
const vga = @import("vga.zig");
const paging = @import("paging.zig");
const gdt = @import("gdt.zig");
const memory = @import("memory.zig");

pub const ProcessState = enum {
    Ready,
    Running,
    Blocked,
    Terminated,
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
};

const MAX_PROCESSES = 256;
var process_table: [MAX_PROCESSES]Process = undefined;
var next_pid: u32 = 1;
pub var current_process: ?*Process = null;
var process_list_head: ?*Process = null;
var idle_process: *Process = undefined;

pub fn getProcessList() ?*Process {
    return process_list_head;
}

pub fn terminateProcess(pid: u32) bool {
    if (pid == 0) return false; // Can't kill idle process

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

pub fn init() void {
    vga.print("Initializing process management...\n");

    for (&process_table) |*proc| {
        proc.state = .Terminated;
        proc.pid = 0;
        proc.next = null;
    }

    idle_process = create_kernel_process("idle", idle_task);
    current_process = idle_process;

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
    
    // Allocate kernel stack for all processes
    proc.kernel_stack = memory.allocPages(1) orelse {
        vga.print("Error: Failed to allocate kernel stack!\n");
        while (true) {
            asm volatile ("hlt");
        }
    };
    
    // Allocate user stack for user processes
    if (privilege == .User) {
        proc.user_stack = memory.allocPages(1) orelse {
            vga.print("Error: Failed to allocate user stack!\n");
            while (true) {
                asm volatile ("hlt");
            }
        };
        
        // Create a new page directory for user process
        proc.page_directory = paging.createUserPageDirectory() catch {
            vga.print("Error: Failed to create user page directory!\n");
            while (true) {
                asm volatile ("hlt");
            }
        };
    } else {
        proc.user_stack = proc.kernel_stack; // Kernel processes use kernel stack
        proc.page_directory = null;
    }

    // Set up context based on privilege level
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

    @memset(&proc.name, 0);
    const copy_len = @min(name.len, proc.name.len - 1);
    @memcpy(proc.name[0..copy_len], name[0..copy_len]);

    proc.next = process_list_head;
    process_list_head = proc;

    vga.print("Created process: ");
    vga.print(name);
    vga.print(" (PID: ");
    print_number(proc.pid);
    vga.print(")\n");

    return proc;
}

pub fn schedule() ?*Process {
    if (current_process == null) {
        return idle_process;
    }

    var next = current_process.?.next;
    if (next == null) {
        next = process_list_head;
    }

    while (next != current_process) {
        if (next.?.state == .Ready) {
            return next;
        }
        next = next.?.next;
        if (next == null) {
            next = process_list_head;
        }
    }

    if (current_process.?.state == .Ready or current_process.?.state == .Running) {
        return current_process;
    }

    return idle_process;
}

pub fn switch_process(old: *Context, new: *Context) void {
    // Save old context
    asm volatile (
        \\pushf
        \\push %%cs
        \\push %%ebp
        \\push %%edi
        \\push %%esi
        \\push %%edx
        \\push %%ecx
        \\push %%ebx
        \\push %%eax
        \\mov %%esp, (%[old])
        :
        : [old] "r" (&old.esp)
        : "memory"
    );
    
    // If switching to a user process, update TSS with kernel stack
    if (current_process != null and current_process.?.privilege == .User) {
        gdt.setKernelStack(@intFromPtr(current_process.?.kernel_stack + current_process.?.stack_size));
    }
    
    // Load new context
    asm volatile (
        \\mov %[new], %%esp
        \\pop %%eax
        \\pop %%ebx
        \\pop %%ecx
        \\pop %%edx
        \\pop %%esi
        \\pop %%edi
        \\pop %%ebp
        \\pop %%ecx  // CS
        \\popf
        :
        : [new] "r" (new.esp)
        : "memory"
    );
}

pub fn yield() void {
    const next = schedule();
    if (next != null and next != current_process) {
        const old_process = current_process.?;
        current_process = next;
        old_process.state = .Ready;
        current_process.?.state = .Running;
        switch_process(&old_process.context, &current_process.?.context);
    }
}

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

pub fn getCurrentProcess() ?*Process {
    return current_process;
}

pub fn switchToProcess(proc: *Process) void {
    if (current_process) |old_proc| {
        old_proc.state = .Ready;
    }
    
    current_process = proc;
    proc.state = .Running;
    
    if (proc.page_directory) |pd| {
        paging.switchPageDirectory(pd);
    }
    
    asm volatile (
        \\mov %[esp], %%esp
        \\mov %[ebp], %%ebp
        \\jmp *%[eip]
        :
        : [esp] "r" (proc.context.esp),
          [ebp] "r" (proc.context.ebp),
          [eip] "r" (proc.context.eip)
    );
}

