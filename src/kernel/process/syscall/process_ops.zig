const abi = @import("abi.zig");
const memory = @import("../../memory/memory.zig");
const paging = @import("../../memory/paging.zig");
const posix = @import("../../utils/posix.zig");
const process_mod = @import("../process.zig");
const protection = @import("../../memory/protection.zig");

pub fn sys_getpid() i32 {
    if (process_mod.current_process) |proc| {
        return @intCast(proc.pid);
    }
    return 0;
}

pub fn sys_yield() i32 {
    process_mod.yield();
    return 0;
}

pub fn sys_fork() i32 {
    const result = posix.fork() catch |err| {
        return switch (err) {
            error.NoCurrentProcess => abi.ENOSYS,
            error.NoProcessSlots => abi.EAGAIN,
            error.OutOfMemory => abi.ENOMEM,
        };
    };
    return result;
}

pub fn sys_execve(path: [*]const u8, argv: usize, envp: usize) i32 {
    var path_buf: [256]u8 = undefined;
    const path_slice = protection.copyStringFromUser(&path_buf, @intFromPtr(path)) catch {
        return abi.EINVAL;
    };

    var argv_array: [32][]const u8 = undefined;
    var argv_count: usize = 0;
    var argv_buffers: [32][256]u8 = undefined;

    if (argv != 0) {
        while (argv_count < 32) {
            const ptr_addr = argv + argv_count * @sizeOf(usize);
            if (!protection.verifyUserPointer(ptr_addr, @sizeOf(usize))) {
                break;
            }

            const str_ptr = @as(*const usize, @ptrFromInt(ptr_addr)).*;
            if (str_ptr == 0) break;

            const arg_slice = protection.copyStringFromUser(&argv_buffers[argv_count], str_ptr) catch {
                break;
            };
            argv_array[argv_count] = arg_slice;
            argv_count += 1;
        }
    }

    var envp_array: [32][]const u8 = undefined;
    var envp_count: usize = 0;
    var envp_buffers: [32][256]u8 = undefined;

    if (envp != 0) {
        while (envp_count < 32) {
            const ptr_addr = envp + envp_count * @sizeOf(usize);
            if (!protection.verifyUserPointer(ptr_addr, @sizeOf(usize))) {
                break;
            }

            const str_ptr = @as(*const usize, @ptrFromInt(ptr_addr)).*;
            if (str_ptr == 0) break;

            const env_slice = protection.copyStringFromUser(&envp_buffers[envp_count], str_ptr) catch {
                break;
            };
            envp_array[envp_count] = env_slice;
            envp_count += 1;
        }
    }

    const argv_slice = argv_array[0..argv_count];
    const envp_slice = envp_array[0..envp_count];

    posix.execve(path_slice, argv_slice, envp_slice) catch |err| {
        return switch (err) {
            error.NoCurrentProcess => abi.ENOSYS,
            error.OutOfMemory => abi.ENOMEM,
            error.FileReadError => abi.ENOENT,
            else => abi.EINVAL,
        };
    };

    return 0;
}

pub fn sys_wait4(pid: i32, status: ?*i32, options: i32, rusage: ?*anyopaque) i32 {
    const result = posix.wait4(pid, status, options, rusage) catch |err| {
        return switch (err) {
            error.NoCurrentProcess => abi.ENOSYS,
            error.InvalidPointer => abi.EINVAL,
        };
    };
    return result;
}

pub fn sys_brk(addr: usize) i32 {
    const proc = process_mod.getCurrentProcess() orelse return @intCast(protection.USER_HEAP_START);
    const current_brk = proc.current_brk;

    if (addr == 0) {
        return @intCast(current_brk);
    }

    if (addr < protection.USER_HEAP_START or addr >= protection.USER_SPACE_END) {
        return @intCast(current_brk);
    }

    const new_brk = (addr + 0xFFF) & ~@as(usize, 0xFFF);

    if (new_brk > current_brk) {
        var page_addr = current_brk;
        while (page_addr < new_brk) : (page_addr += 0x1000) {
            const phys_page = memory.allocatePhysicalPage() orelse {
                var cleanup_addr = current_brk;
                while (cleanup_addr < page_addr) : (cleanup_addr += 0x1000) {
                    paging.unmap_page(@intCast(cleanup_addr));
                }
                return @intCast(current_brk);
            };
            paging.mapPage(@intCast(page_addr), phys_page, paging.PAGE_PRESENT | paging.PAGE_WRITABLE | paging.PAGE_USER);
        }
    } else if (new_brk < current_brk) {
        var page_addr = new_brk;
        while (page_addr < current_brk) : (page_addr += 0x1000) {
            paging.unmap_page(@intCast(page_addr));
        }
    }

    proc.current_brk = new_brk;
    return @intCast(proc.current_brk);
}
