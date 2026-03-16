const abi = @import("abi.zig");
const common = @import("common.zig");
const x86 = @import("../../../arch/x86.zig");
const ipc = @import("../ipc.zig");
const kernel_signal = @import("../signal.zig");
const memory = @import("../../memory/memory.zig");
const mmap = @import("../../memory/mmap.zig");
const paging = @import("../../memory/paging.zig");
const posix = @import("../../utils/posix.zig");
const process_mod = @import("../process.zig");
const protection = @import("../../memory/protection.zig");
const vfs = @import("../../fs/vfs.zig");

const MAX_EXECVE_ARGS: usize = 32;
const MAX_EXECVE_ENV: usize = 32;
const EXECVE_STRING_BUFFER_SIZE: usize = common.USER_PATH_BUFFER_SIZE;

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

pub fn sys_exit(status: i32) i32 {
    if (process_mod.getEffectiveCurrent()) |proc| {
        process_mod.cleanupStdioRedirects(proc);
        proc.state = .Terminated;
        proc.exit_code = status;

        if (proc.parent_pid != 0) {
            if (process_mod.getProcessByPid(proc.parent_pid)) |parent| {
                kernel_signal.sendSignal(parent, kernel_signal.SIGCHLD);
                process_mod.switchToProcess(parent);
            }
        }

        while (true) {
            process_mod.yield();
            x86.hlt();
        }
    }

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
    var path_buf: [EXECVE_STRING_BUFFER_SIZE]u8 = undefined;
    const path_slice = protection.copyStringFromUser(&path_buf, @intFromPtr(path)) catch {
        return abi.EINVAL;
    };

    var argv_array: [MAX_EXECVE_ARGS][]const u8 = undefined;
    var argv_count: usize = 0;
    var argv_buffers: [MAX_EXECVE_ARGS][EXECVE_STRING_BUFFER_SIZE]u8 = undefined;

    if (argv != 0) {
        while (argv_count < argv_array.len) {
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

    var envp_array: [MAX_EXECVE_ENV][]const u8 = undefined;
    var envp_count: usize = 0;
    var envp_buffers: [MAX_EXECVE_ENV][EXECVE_STRING_BUFFER_SIZE]u8 = undefined;

    if (envp != 0) {
        while (envp_count < envp_array.len) {
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

pub fn sys_mmap(addr: usize, length: usize, prot: i32, flags: i32, fd: i32, offset: i32) i32 {
    if (length == 0) {
        return abi.EINVAL;
    }

    const proc = process_mod.getCurrentProcess() orelse return abi.ENOSYS;
    const map_prot: u32 = @bitCast(prot);
    const map_flags: u32 = @bitCast(flags);

    var vnode: ?*vfs.VNode = null;
    var open_flags: u32 = vfs.O_RDONLY;
    var file_offset: u64 = 0;
    var file_bytes: usize = 0;
    defer if (vnode) |node| vfs.releaseVNode(node);

    if ((map_flags & abi.MAP_ANONYMOUS) == 0) {
        if (fd < abi.FD_OFFSET or offset < 0 or (@as(u32, @bitCast(offset)) & 0xFFF) != 0) {
            return abi.EINVAL;
        }

        const vfs_fd: u32 = @intCast(fd - abi.FD_OFFSET);
        open_flags = vfs.getFileFlags(vfs_fd) catch return abi.EBADF;
        vnode = vfs.getVNodeFromFd(vfs_fd) catch return abi.EBADF;

        if (vnode.?.file_type != .Regular) {
            return abi.ENODEV;
        }

        const access_mode = open_flags & 0x3;
        if ((map_prot & abi.PROT_READ) != 0 and access_mode == vfs.O_WRONLY) {
            return abi.EACCES;
        }
        if ((map_flags & abi.MAP_SHARED) != 0 and (map_prot & abi.PROT_WRITE) != 0 and access_mode == vfs.O_RDONLY) {
            return abi.EACCES;
        }

        file_offset = @intCast(offset);
        if (file_offset > vnode.?.size) {
            file_bytes = 0;
        } else {
            file_bytes = @intCast(@min(@as(u64, @intCast(length)), vnode.?.size - file_offset));
        }
    } else if (offset != 0) {
        return abi.EINVAL;
    }

    const result_addr = mmap.mmap(proc, addr, length, map_prot, map_flags, vnode, open_flags & 0x3, file_offset, file_bytes) catch |err| {
        return switch (err) {
            error.InvalidArgument => abi.EINVAL,
            error.NoMemory => abi.ENOMEM,
            error.AccessDenied => abi.EACCES,
            error.InvalidFd => abi.EBADF,
            error.NotMapped => abi.EINVAL,
            error.TooManyMappings => abi.ENOMEM,
        };
    };

    return @intCast(result_addr);
}

pub fn sys_msgget(max_messages: u32) i32 {
    const pid = if (process_mod.current_process) |proc| proc.pid else return abi.ENOSYS;
    const clamped = if (max_messages == 0)
        ipc.DEFAULT_MESSAGE_QUEUE_CAPACITY
    else
        @min(max_messages, ipc.MAX_MESSAGE_QUEUE_CAPACITY);

    if (ipc.getMessageQueue(pid) != null) return 0;

    _ = ipc.createMessageQueue(pid, clamped) catch return abi.ENOMEM;
    return 0;
}

pub fn sys_msgsnd(receiver_pid: u32, buf: [*]const u8, len: usize) i32 {
    if (!protection.verifyUserPointer(@intFromPtr(buf), len)) return abi.EINVAL;
    const sender_pid = if (process_mod.current_process) |proc| proc.pid else return abi.ENOSYS;

    const msg_len = @min(len, ipc.MESSAGE_DATA_SIZE);
    var kernel_buffer: [ipc.MESSAGE_DATA_SIZE]u8 = undefined;
    protection.copyFromUser(kernel_buffer[0..msg_len], @intFromPtr(buf)) catch return abi.EINVAL;

    ipc.sendMessage(sender_pid, receiver_pid, .Data, kernel_buffer[0..msg_len]) catch |err| {
        return switch (err) {
            error.OutOfMemory => abi.ENOMEM,
            error.ReceiverNotFound => abi.ESRCH,
            error.QueueFull => abi.EAGAIN,
        };
    };
    return 0;
}

pub fn sys_msgrcv(buf: [*]u8, size: usize, flags: i32) i32 {
    if (!protection.verifyUserPointer(@intFromPtr(buf), size)) return abi.EINVAL;
    const pid = if (process_mod.current_process) |proc| proc.pid else return abi.ENOSYS;

    const queue = ipc.getMessageQueue(pid) orelse return abi.ENOENT;

    const msg = if (flags != 0) queue.tryReceive() else queue.receive();
    if (msg == null) return 0;

    const m = msg.?;
    const copy_len = @min(m.data_len, @as(u32, @intCast(size)));
    protection.copyToUser(@intFromPtr(buf), m.data[0..copy_len]) catch {
        ipc.freeMessage(m);
        return abi.EINVAL;
    };
    ipc.freeMessage(m);
    return @intCast(copy_len);
}

pub fn sys_munmap(addr: usize, length: usize) i32 {
    const proc = process_mod.getCurrentProcess() orelse return abi.ENOSYS;
    mmap.munmap(proc, addr, length) catch |err| {
        return switch (err) {
            error.InvalidArgument => abi.EINVAL,
            error.NoMemory => abi.ENOMEM,
            error.AccessDenied => abi.EACCES,
            error.InvalidFd => abi.EBADF,
            error.NotMapped => abi.EINVAL,
            error.TooManyMappings => abi.ENOMEM,
        };
    };
    return 0;
}

pub fn sys_getppid() i32 {
    if (process_mod.current_process) |proc| {
        return @intCast(proc.parent_pid);
    }
    return 0;
}

pub fn sys_getpgid(pid: i32) i32 {
    if (pid == 0) {
        if (process_mod.current_process) |proc| {
            return @intCast(proc.process_group);
        }
        return abi.ESRCH;
    }

    if (pid > 0) {
        if (process_mod.getProcessByPid(@intCast(pid))) |proc| {
            return @intCast(proc.process_group);
        }
    }
    return abi.ESRCH;
}

pub fn sys_setpgid(pid: i32, pgid: i32) i32 {
    const target = blk: {
        if (pid == 0) {
            break :blk process_mod.current_process orelse return abi.ESRCH;
        }
        if (pid > 0) {
            break :blk process_mod.getProcessByPid(@as(u32, @intCast(pid))) orelse return abi.ESRCH;
        }
        return abi.EINVAL;
    };

    if (pgid == 0) {
        target.process_group = target.pid;
    } else if (pgid > 0) {
        target.process_group = @intCast(pgid);
    } else {
        return abi.EINVAL;
    }

    return 0;
}

pub fn sys_setsid() i32 {
    const proc = process_mod.current_process orelse return abi.EPERM;
    proc.process_group = proc.pid;
    return @intCast(proc.pid);
}
