const std = @import("std");
const process = @import("../process/process.zig");
const memory = @import("../memory/memory.zig");
const paging = @import("../memory/paging.zig");
const protection = @import("../memory/protection.zig");
const elf = @import("../elf/elf.zig");
const gdt = @import("../interrupts/gdt.zig");

pub const WEXITED = 1;
pub const WSIGNALED = 2;
pub const WSTOPPED = 4;
pub const WCONTINUED = 8;

pub const WNOHANG = 1;
pub const WUNTRACED = 2;

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

    child.pid = process.next_pid;
    process.next_pid += 1;
    child.state = .Ready;
    child.privilege = parent.privilege;
    child.stack_size = parent.stack_size;
    child.exit_code = 0;
    child.parent_pid = parent.pid;
    child.process_group = parent.process_group;

    @memset(&child.name, 0);
    @memcpy(child.name[0..child_name.len], child_name);

    child.kernel_stack = memory.allocPages(1) orelse return error.OutOfMemory;

    child.page_directory = try paging.createUserPageDirectory();

    try copyAddressSpace(parent, child);

    child.context = parent.context;

    if (process.current_process == parent) {
        child.context.eax = 0;

        child.next = process.process_list_head;
        process.process_list_head = child;

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

    var addr: u32 = 0;
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

    const elf_info = try elf.loadElfIntoProcess(current, path);

    current.entry_point = @ptrFromInt(elf_info.entry_point);
    current.context.eip = elf_info.entry_point;

    const stack_top = protection.USER_STACK_TOP;
    const stack_size = 0x10000;
    const stack_bottom = stack_top - stack_size;

    var page_addr: u32 = stack_bottom;
    while (page_addr < stack_top) : (page_addr += 0x1000) {
        const phys_addr = memory.allocatePhysicalPage() orelse return error.OutOfMemory;
        paging.mapPage(page_addr, phys_addr, paging.PAGE_PRESENT | paging.PAGE_WRITABLE | paging.PAGE_USER);
    }

    var stack_ptr: u32 = stack_top;

    // SAFETY: filled by the following loop that copies environment strings to the stack
    var envp_ptrs: [32]usize = undefined;
    var envp_count: usize = 0;
    for (envp) |env| {
        if (envp_count >= 32) break;
        stack_ptr -= env.len + 1;
        stack_ptr &= ~@as(u32, 0x3);
        const dest: [*]u8 = @ptrFromInt(stack_ptr);
        @memcpy(dest[0..env.len], env);
        dest[env.len] = 0;
        envp_ptrs[envp_count] = stack_ptr;
        envp_count += 1;
    }

    // SAFETY: filled by the following loop that copies argument strings to the stack
    var argv_ptrs: [32]usize = undefined;
    var argv_count: usize = 0;
    for (argv) |arg| {
        if (argv_count >= 32) break;
        stack_ptr -= arg.len + 1;
        stack_ptr &= ~@as(u32, 0x3);
        const dest: [*]u8 = @ptrFromInt(stack_ptr);
        @memcpy(dest[0..arg.len], arg);
        dest[arg.len] = 0;
        argv_ptrs[argv_count] = stack_ptr;
        argv_count += 1;
    }

    stack_ptr &= ~@as(u32, 0xF);

    stack_ptr -= @sizeOf(usize);
    @as(*usize, @ptrFromInt(stack_ptr)).* = 0;
    var i = envp_count;
    while (i > 0) {
        i -= 1;
        stack_ptr -= @sizeOf(usize);
        @as(*usize, @ptrFromInt(stack_ptr)).* = envp_ptrs[i];
    }
    const envp_array_ptr = stack_ptr;

    stack_ptr -= @sizeOf(usize);
    @as(*usize, @ptrFromInt(stack_ptr)).* = 0;
    i = argv_count;
    while (i > 0) {
        i -= 1;
        stack_ptr -= @sizeOf(usize);
        @as(*usize, @ptrFromInt(stack_ptr)).* = argv_ptrs[i];
    }
    const argv_array_ptr = stack_ptr;

    stack_ptr -= @sizeOf(usize);
    @as(*usize, @ptrFromInt(stack_ptr)).* = envp_array_ptr;
    stack_ptr -= @sizeOf(usize);
    @as(*usize, @ptrFromInt(stack_ptr)).* = argv_array_ptr;
    stack_ptr -= @sizeOf(usize);
    @as(*usize, @ptrFromInt(stack_ptr)).* = argv_count;

    current.context.esp = stack_ptr;
    current.context.ebp = stack_ptr;

    current.context.cs = gdt.USER_CODE_SEG | 0x3;
    current.context.ss = gdt.USER_DATA_SEG | 0x3;

    process.switchToProcess(current);
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
        var child_rusage: RUsage = std.mem.zeroes(RUsage);

        var proc = process.getProcessList();
        while (proc) |p| : (proc = p.next) {
            const target_match = if (pid == -1) true else if (pid > 0) (p.pid == @as(u32, @intCast(pid))) else false;
            if (p.parent_pid == parent.pid and target_match) {
                if (p.state == .Terminated) {
                    found_child = true;
                    child_pid = @intCast(p.pid);
                    child_status = p.exit_code;

                    child_rusage.utime_sec = 0;
                    child_rusage.utime_usec = 0;
                    child_rusage.stime_sec = 0;
                    child_rusage.stime_usec = 0;
                    child_rusage.maxrss = 0;
                    child_rusage.nvcsw = 0;
                    child_rusage.nivcsw = 0;

                    p.state = .Terminated;
                    if (p.page_directory) |pd| {
                        memory.freePages(@as([*]u8, @ptrFromInt(@intFromPtr(pd))), 1);
                    }
                    memory.freePages(p.kernel_stack, 1);

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

        parent.state = .Waiting;
        process.yield();
    }
}

fn freeUserMemory(proc: *process.Process) void {
    if (proc.page_directory == null) return;

    const old_page_dir = paging.getCurrentPageDirectory();
    paging.switchPageDirectory(proc.page_directory.?);
    defer paging.switchPageDirectory(old_page_dir);

    var addr: u32 = 0;
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
