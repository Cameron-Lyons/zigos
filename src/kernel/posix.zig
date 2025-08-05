const std = @import("std");
const process = @import("process.zig");
const memory = @import("memory.zig");
const paging = @import("paging.zig");
const vga = @import("vga.zig");
const protection = @import("protection.zig");
const elf = @import("elf.zig");
const vfs = @import("vfs.zig");
const gdt = @import("gdt.zig");

// Process status codes
pub const WEXITED = 1;
pub const WSIGNALED = 2;
pub const WSTOPPED = 4;
pub const WCONTINUED = 8;

// Wait options
pub const WNOHANG = 1;
pub const WUNTRACED = 2;

// Fork - Create a copy of the current process
pub fn fork() !i32 {
    const parent = process.getCurrentProcess() orelse return error.NoCurrentProcess;
    
    // Allocate a new process
    const child_name = "forked_process";
    var child: *process.Process = undefined;
    
    // Find a free process slot
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
    
    // Initialize child process
    child.pid = process.next_pid;
    process.next_pid += 1;
    child.state = .Ready;
    child.privilege = parent.privilege;
    child.stack_size = parent.stack_size;
    child.exit_code = 0;
    
    // Copy process name
    @memset(&child.name, 0);
    @memcpy(child.name[0..child_name.len], child_name);
    
    // Allocate kernel stack for child
    child.kernel_stack = memory.allocPages(1) orelse return error.OutOfMemory;
    
    // Create page directory for child
    child.page_directory = try paging.createUserPageDirectory();
    
    // Copy parent's memory space
    try copyAddressSpace(parent, child);
    
    // Copy parent's context
    child.context = parent.context;
    
    // Set return values
    // Parent gets child PID, child gets 0
    if (process.current_process == parent) {
        // We're in parent, return child PID
        child.context.eax = 0; // Child will get 0
        
        // Add child to process list
        child.next = process.process_list_head;
        process.process_list_head = child;
        
        return @intCast(child.pid);
    }
    
    return 0;
}

// Copy address space from parent to child
fn copyAddressSpace(parent: *process.Process, child: *process.Process) !void {
    const old_page_dir = paging.getCurrentPageDirectory();
    
    // Switch to parent's page directory
    if (parent.page_directory) |pd| {
        paging.switchPageDirectory(pd);
    }
    
    defer {
        // Restore original page directory
        paging.switchPageDirectory(old_page_dir);
    }
    
    // Copy all user-space pages
    var addr: u32 = 0;
    while (addr < protection.USER_SPACE_END) : (addr += 0x1000) {
        if (paging.get_physical_address(addr)) |_| {
            // Allocate new physical page for child
            const child_phys = memory.allocatePhysicalPage() orelse return error.OutOfMemory;
            
            // Map in child's page directory
            const temp_page_dir = paging.getCurrentPageDirectory();
            paging.switchPageDirectory(child.page_directory.?);
            paging.mapPage(addr, child_phys, paging.PAGE_PRESENT | paging.PAGE_WRITABLE | paging.PAGE_USER);
            paging.switchPageDirectory(temp_page_dir);
            
            // Copy page contents
            const parent_page = @as([*]u8, @ptrFromInt(addr));
            const temp_addr = 0xFFC00000; // Temporary mapping address
            
            // Map child page temporarily
            paging.mapPage(temp_addr, child_phys, paging.PAGE_PRESENT | paging.PAGE_WRITABLE);
            const child_page = @as([*]u8, @ptrFromInt(temp_addr));
            
            // Copy data
            @memcpy(child_page[0..0x1000], parent_page[0..0x1000]);
            
            // Unmap temporary mapping
            paging.unmap_page(temp_addr);
        }
    }
}

// Exec - Replace current process with a new program
pub fn execve(path: []const u8, argv: []const []const u8, envp: []const []const u8) !void {
    _ = argv; // TODO: Pass arguments to new process
    _ = envp; // TODO: Pass environment to new process
    
    const current = process.getCurrentProcess() orelse return error.NoCurrentProcess;
    
    // Free current process memory (except kernel stack)
    freeUserMemory(current);
    
    // Load new executable
    const elf_info = try elf.loadElfIntoProcess(current, path);
    
    // Update entry point
    current.entry_point = @ptrFromInt(elf_info.entry_point);
    current.context.eip = elf_info.entry_point;
    
    // Set up new stack
    const stack_top = protection.USER_STACK_TOP;
    const stack_size = 0x10000; // 64KB stack
    const stack_bottom = stack_top - stack_size;
    
    // Allocate stack pages
    var page_addr: u32 = stack_bottom;
    while (page_addr < stack_top) : (page_addr += 0x1000) {
        const phys_addr = memory.allocatePhysicalPage() orelse return error.OutOfMemory;
        paging.mapPage(page_addr, phys_addr, paging.PAGE_PRESENT | paging.PAGE_WRITABLE | paging.PAGE_USER);
    }
    
    // Set stack pointer
    current.context.esp = stack_top - 16;
    current.context.ebp = current.context.esp;
    
    // Set up segments for user mode
    current.context.cs = gdt.USER_CODE_SEG | 0x3;
    current.context.ss = gdt.USER_DATA_SEG | 0x3;
    
    // Jump to new program
    process.switchToProcess(current);
}

// Wait - Wait for child process to change state
pub fn wait4(pid: i32, status: ?*i32, options: i32, rusage: ?*anyopaque) !i32 {
    _ = rusage; // TODO: Resource usage statistics
    
    const parent = process.getCurrentProcess() orelse return error.NoCurrentProcess;
    
    while (true) {
        // Search for matching child
        var found_child = false;
        var child_pid: i32 = -1;
        var child_status: i32 = 0;
        
        var proc = process.getProcessList();
        while (proc) |p| : (proc = p.next) {
            // Check if this is our child (simplified - should track parent-child relationships)
            if (pid == -1 or p.pid == pid) {
                if (p.state == .Terminated) {
                    found_child = true;
                    child_pid = @intCast(p.pid);
                    child_status = p.exit_code;
                    
                    // Clean up child process
                    p.state = .Terminated;
                    if (p.page_directory) |pd| {
                        // TODO: Free page directory
                        _ = pd;
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
            return child_pid;
        }
        
        // No matching child found
        if (options & WNOHANG != 0) {
            return 0; // Don't block
        }
        
        // Block until a child terminates
        parent.state = .Blocked;
        process.yield();
    }
}

// Free user memory of a process
fn freeUserMemory(proc: *process.Process) void {
    if (proc.page_directory == null) return;
    
    const old_page_dir = paging.getCurrentPageDirectory();
    paging.switchPageDirectory(proc.page_directory.?);
    defer paging.switchPageDirectory(old_page_dir);
    
    // Free all user-space pages
    var addr: u32 = 0;
    while (addr < protection.USER_SPACE_END) : (addr += 0x1000) {
        paging.unmap_page(addr);
    }
}

// Helper functions for wait status
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