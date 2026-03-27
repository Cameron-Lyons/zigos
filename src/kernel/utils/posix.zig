const std = @import("std");
const console = @import("console.zig");
const mmap = @import("../memory/mmap.zig");
const process = @import("../process/process.zig");
const memory = @import("../memory/memory.zig");
const paging = @import("../memory/paging.zig");
const protection = @import("../memory/protection.zig");
const elf = @import("../elf/elf.zig");
const gdt = @import("../interrupts/gdt.zig");
const signal = @import("../process/signal.zig");
const scheduler = @import("../process/scheduler.zig");

pub const WEXITED = 1;
pub const WSIGNALED = 2;
pub const WSTOPPED = 4;
pub const WCONTINUED = 8;

pub const WNOHANG = 1;
pub const WUNTRACED = 2;

const StartupInfo = extern struct {
    argc: usize,
    argv: usize,
    envp: usize,
};

pub fn fork() !i32 {
    const parent = process.getCurrentProcess() orelse return error.NoCurrentProcess;

    const child_name = "forked_process";
    // SAFETY: assigned by scanning the process table in the loop below
    var child: *process.Process = undefined;

    var i: usize = 0;
    while (i < 256) : (i += 1) {
        if (process.process_table[i].state == .Terminated) {
            child = &process.process_table[i];
            break;
        }
    }

    if (i == 256) {
        return error.NoProcessSlots;
    }

    const child_pid = process.next_pid;
    child.pid = child_pid;
    process.pid_lookup[child_pid % 256] = child;
    process.next_pid += 1;
    child.* = .{
        .pid = child_pid,
        .state = .Ready,
        .privilege = parent.privilege,
        .context = parent.context,
        .kernel_stack = undefined,
        .user_stack = parent.user_stack,
        .stack_size = parent.stack_size,
        .name = [_]u8{0} ** 64,
        .next = process.process_list_head,
        .wait_next = null,
        .exit_code = 0,
        .page_directory = null,
        .entry_point = parent.entry_point,
        .priority = parent.priority,
        .nice_value = parent.nice_value,
        .time_slice = parent.time_slice,
        .creds = parent.creds,
        .parent_pid = parent.pid,
        .process_group = if (parent.process_group != 0) parent.process_group else parent.pid,
        .alarm_time = 0,
        .umask = parent.umask,
        .cwd_path = parent.cwd_path,
        .cwd_len = parent.cwd_len,
        .chroot_path = parent.chroot_path,
        .chroot_len = parent.chroot_len,
        .current_brk = parent.current_brk,
        .rlimits = parent.rlimits,
        .itimers = parent.itimers,
        .memory_mappings = parent.memory_mappings,
        .signals = parent.signals,
        .stdin_redirect = parent.stdin_redirect,
        .stdout_redirect = parent.stdout_redirect,
        .stderr_redirect = parent.stderr_redirect,
        .extended_idx = parent.extended_idx,
    };
    child.signals.pending = signal.SignalQueue.init();
    @memcpy(child.name[0..child_name.len], child_name);

    child.kernel_stack = process.allocateProcessStack() orelse return error.OutOfMemory;

    child.page_directory = paging.createUserPageDirectory() catch |err| {
        process.releaseProcessStack(child.kernel_stack);
        return err;
    };

    copyAddressSpace(parent, child) catch |err| {
        process.releaseProcessStack(child.kernel_stack);
        return err;
    };
    mmap.cloneMappings(parent, child);

    child.context.cr3 = @intFromPtr(child.page_directory);

    if (process.current_process == parent) {
        child.context.eax = 0;
        process.process_list_head = child;

        const priority = if (parent.privilege == .Kernel) scheduler.Priority.High else scheduler.Priority.Normal;
        _ = scheduler.registerProcess(child, priority);

        return @intCast(child.pid);
    }

    return 0;
}

fn copyAddressSpace(parent: *process.Process, child: *process.Process) !void {
    const old_page_dir = paging.getCurrentPageDirectory();

    if (parent.page_directory) |pd| {
        paging.switchPageDirectory(pd);
    }

    defer {
        paging.switchPageDirectory(old_page_dir);
    }

    var addr: u32 = protection.USER_PROGRAM_START;
    while (addr < protection.USER_SPACE_END) : (addr += 0x1000) {
        if (paging.get_physical_address(addr)) |_| {
            const child_phys = memory.allocatePhysicalPage() orelse return error.OutOfMemory;

            const temp_page_dir = paging.getCurrentPageDirectory();
            paging.switchPageDirectory(child.page_directory.?);
            paging.mapPage(addr, child_phys, paging.PAGE_PRESENT | paging.PAGE_WRITABLE | paging.PAGE_USER);
            paging.switchPageDirectory(temp_page_dir);

            const parent_page: [*]u8 = @ptrFromInt(addr);
            const temp_addr = 0xFFC00000;

            paging.mapPage(temp_addr, child_phys, paging.PAGE_PRESENT | paging.PAGE_WRITABLE);
            const child_page: [*]u8 = @ptrFromInt(temp_addr);

            @memcpy(child_page[0..0x1000], parent_page[0..0x1000]);

            paging.unmap_page(temp_addr);
        }
    }
}

pub fn execve(path: []const u8, argv: []const []const u8, envp: []const []const u8) !void {
    const current = process.getCurrentProcess() orelse return error.NoCurrentProcess;

    freeUserMemory(current);

    if (current.page_directory == null) {
        current.page_directory = try paging.createUserPageDirectory();
    }

    const elf_info = try elf.loadElfIntoProcess(current, path);

    const old_page_dir = paging.getCurrentPageDirectory();
    paging.switchPageDirectory(current.page_directory.?);
    defer paging.switchPageDirectory(old_page_dir);

    try prepareUserExecution(current, elf_info.entry_point, argv, envp);

    process.switchToProcess(current);
}

pub fn execveFromData(data: []const u8, argv: []const []const u8, envp: []const []const u8) !void {
    const current = process.getCurrentProcess() orelse return error.NoCurrentProcess;

    freeUserMemory(current);

    if (current.page_directory == null) {
        current.page_directory = try paging.createUserPageDirectory();
    }

    const elf_info = try elf.loadElfDataIntoProcess(current, data);

    const old_page_dir = paging.getCurrentPageDirectory();
    paging.switchPageDirectory(current.page_directory.?);
    defer paging.switchPageDirectory(old_page_dir);

    try prepareUserExecution(current, elf_info.entry_point, argv, envp);

    @import("../interrupts/idt.zig").init();
    process.switchToProcess(current);
}

fn prepareUserExecution(current: *process.Process, entry_point: u32, argv: []const []const u8, envp: []const []const u8) !void {
    current.entry_point = entry_point;
    current.current_brk = protection.USER_HEAP_START;
    current.context.eip = entry_point;

    const stack_top = protection.USER_STACK_TOP;
    const stack_size = 0x10000;
    const stack_bottom = stack_top - stack_size;
    const startup_page = protection.USER_STARTUP_PAGE;

    var page_addr: u32 = stack_bottom;
    while (page_addr < stack_top) : (page_addr += 0x1000) {
        const phys_addr = memory.allocatePhysicalPage() orelse return error.OutOfMemory;
        paging.mapPage(page_addr, phys_addr, paging.PAGE_PRESENT | paging.PAGE_WRITABLE | paging.PAGE_USER);
    }

    const startup_phys = memory.allocatePhysicalPage() orelse return error.OutOfMemory;
    paging.mapPage(startup_page, startup_phys, paging.PAGE_PRESENT | paging.PAGE_WRITABLE | paging.PAGE_USER);

    const startup_base: usize = startup_page;
    const startup_limit: usize = startup_base + 0x1000;
    const startup_info: *StartupInfo = @ptrFromInt(startup_base);
    var cursor = startup_base + @sizeOf(StartupInfo);

    const argv_array_addr = cursor;
    cursor += (argv.len + 1) * @sizeOf(usize);
    const envp_array_addr = cursor;
    cursor += (envp.len + 1) * @sizeOf(usize);

    if (cursor > startup_limit) return error.OutOfMemory;

    const argv_array: [*]usize = @ptrFromInt(argv_array_addr);
    const envp_array: [*]usize = @ptrFromInt(envp_array_addr);

    var i: usize = 0;
    while (i < argv.len) : (i += 1) {
        const arg = argv[i];
        if (cursor + arg.len + 1 > startup_limit) return error.OutOfMemory;
        argv_array[i] = cursor;
        const dest: [*]u8 = @ptrFromInt(cursor);
        @memcpy(dest[0..arg.len], arg);
        dest[arg.len] = 0;
        cursor += arg.len + 1;
    }
    argv_array[argv.len] = 0;

    i = 0;
    while (i < envp.len) : (i += 1) {
        const env = envp[i];
        if (cursor + env.len + 1 > startup_limit) return error.OutOfMemory;
        envp_array[i] = cursor;
        const dest: [*]u8 = @ptrFromInt(cursor);
        @memcpy(dest[0..env.len], env);
        dest[env.len] = 0;
        cursor += env.len + 1;
    }
    envp_array[envp.len] = 0;

    startup_info.* = .{
        .argc = argv.len,
        .argv = argv_array_addr,
        .envp = envp_array_addr,
    };

    current.context.esp = stack_top;
    current.context.ebp = stack_top;
    current.context.cs = gdt.USER_CODE_SEG | 0x3;
    current.context.ss = gdt.USER_DATA_SEG | 0x3;
}

pub const RUsage = extern struct {
    utime_sec: i32,
    utime_usec: i32,
    stime_sec: i32,
    stime_usec: i32,
    maxrss: i32,
    ixrss: i32,
    idrss: i32,
    isrss: i32,
    minflt: i32,
    majflt: i32,
    nswap: i32,
    inblock: i32,
    oublock: i32,
    msgsnd: i32,
    msgrcv: i32,
    nsignals: i32,
    nvcsw: i32,
    nivcsw: i32,
};

pub fn wait4(pid: i32, status: ?*i32, options: i32, rusage: ?*anyopaque) !i32 {
    const parent = process.getCurrentProcess() orelse return error.NoCurrentProcess;

    while (true) {
        var found_child = false;
        var child_pid: i32 = -1;
        var child_status: i32 = 0;
        var child_rusage = emptyRUsage();

        var proc = process.getProcessList();
        while (proc) |p| : (proc = p.next) {
            const target_match = if (pid == -1) true else if (pid > 0) (p.pid == @as(u32, @intCast(pid))) else false;
            if (p.parent_pid == parent.pid and target_match) {
                if (p.state == .Terminated) {
                    found_child = true;
                    child_pid = @intCast(p.pid);
                    child_status = p.exit_code;
                    reapExitedProcess(p);

                    break;
                }
            }
        }

        if (found_child) {
            if (status) |s| {
                protection.copyToUser(@intFromPtr(s), std.mem.asBytes(&child_status)) catch {
                    return error.InvalidPointer;
                };
            }

            if (rusage) |ru| {
                const ru_ptr = @intFromPtr(ru);
                protection.copyToUser(ru_ptr, std.mem.asBytes(&child_rusage)) catch {
                    return error.InvalidPointer;
                };
            }

            return child_pid;
        }

        if (options & WNOHANG != 0) {
            return 0;
        }

        scheduler.blockProcess(parent);
        process.yield();
    }
}

pub fn waitForProcess(pid: u32) !i32 {
    const parent = process.getCurrentProcess() orelse return error.NoCurrentProcess;
    while (true) {
        var proc = process.getProcessList();
        var found = false;
        while (proc) |current| : (proc = current.next) {
            if (current.pid != pid) continue;
            found = true;
            if (current.state == .Terminated or current.state == .Zombie) {
                const exit_code = current.exit_code;
                reapExitedProcess(current);
                return exit_code;
            }
            break;
        }

        if (!found) return error.ProcessNotFound;
        scheduler.blockProcess(parent);
        process.yield();
    }
}

pub fn pollProcessExit(pid: u32) !?i32 {
    var proc = process.getProcessList();
    while (proc) |current| : (proc = current.next) {
        if (current.pid != pid) continue;
        if (current.state == .Terminated or current.state == .Zombie) {
            const exit_code = current.exit_code;
            reapExitedProcess(current);
            return exit_code;
        }
        return null;
    }
    return error.ProcessNotFound;
}

pub const ProcessWaitResult = union(enum) {
    exited: i32,
    stopped,
};

pub fn waitForProcessEvent(pid: u32) !ProcessWaitResult {
    const parent = process.getCurrentProcess() orelse return error.NoCurrentProcess;
    while (true) {
        var proc = process.getProcessList();
        var found = false;
        while (proc) |current| : (proc = current.next) {
            if (current.pid != pid) continue;
            found = true;
            if (current.state == .Terminated or current.state == .Zombie) {
                const exit_code = current.exit_code;
                reapExitedProcess(current);
                return .{ .exited = exit_code };
            }
            if (current.state == .Stopped) {
                return .stopped;
            }
            break;
        }

        if (!found) return error.ProcessNotFound;
        scheduler.blockProcess(parent);
        process.yield();
    }
}

fn reapExitedProcess(proc: *process.Process) void {
    const stack_pages = proc.stack_size / 4096;
    const kernel_stack = proc.kernel_stack;
    const user_stack = proc.user_stack;

    proc.state = .Terminated;
    process.unregisterAndRemoveProcess(proc);
    freeUserMemory(proc);
    if (stack_pages > 0) {
        process.releaseProcessStack(kernel_stack);
        if (user_stack != kernel_stack) {
            process.releaseProcessStack(user_stack);
        }
    }
    proc.page_directory = null;
}

fn emptyRUsage() RUsage {
    return std.mem.zeroes(RUsage);
}

fn freeUserMemory(proc: *process.Process) void {
    if (proc.page_directory == null) return;

    const old_page_dir = paging.getCurrentPageDirectory();
    paging.switchPageDirectory(proc.page_directory.?);
    defer paging.switchPageDirectory(old_page_dir);

    mmap.releaseProcessMappings(proc);

    var addr: u32 = protection.USER_PROGRAM_START;
    while (addr < protection.USER_SPACE_END) : (addr += 0x1000) {
        paging.unmap_page(addr);
    }
}

pub fn WIFEXITED(status: i32) bool {
    return (status & 0x7F) == 0;
}

pub fn WEXITSTATUS(status: i32) u8 {
    return @intCast((status >> 8) & 0xFF);
}

pub fn WIFSIGNALED(status: i32) bool {
    return ((status & 0x7F) + 1) >> 1 > 0;
}

pub fn WTERMSIG(status: i32) u8 {
    return @intCast(status & 0x7F);
}
