const std = @import("std");
const abi = @import("abi.zig");
const mmap = @import("../../memory/mmap.zig");
const process = @import("../process.zig");
const protection = @import("../../memory/protection.zig");

const Rlimit = process.Rlimit;

pub fn sys_membarrier(cmd: u32, flags: u32) i32 {
    _ = flags;

    switch (cmd) {
        abi.MEMBARRIER_CMD_QUERY => {
            return @intCast(abi.MEMBARRIER_CMD_GLOBAL | abi.MEMBARRIER_CMD_GLOBAL_EXPEDITED | abi.MEMBARRIER_CMD_PRIVATE_EXPEDITED);
        },
        abi.MEMBARRIER_CMD_GLOBAL, abi.MEMBARRIER_CMD_GLOBAL_EXPEDITED, abi.MEMBARRIER_CMD_PRIVATE_EXPEDITED => {
            return 0;
        },
        abi.MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED, abi.MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED => {
            return 0;
        },
        else => return abi.EINVAL,
    }
}

pub fn sys_mlock(addr: usize, len: usize) i32 {
    _ = addr;
    _ = len;
    return 0;
}

pub fn sys_munlock(addr: usize, len: usize) i32 {
    _ = addr;
    _ = len;
    return 0;
}

pub fn sys_mlockall(flags: u32) i32 {
    _ = flags;
    return 0;
}

pub fn sys_munlockall() i32 {
    return 0;
}

pub fn sys_madvise(addr: usize, length: usize, advice: u32) i32 {
    _ = addr;
    _ = length;
    _ = advice;
    return 0;
}

pub fn sys_mincore(addr: usize, length: usize, vec: usize) i32 {
    if (!protection.verifyUserPointer(vec, pageCount(length))) return abi.EFAULT;
    _ = addr;

    const pages = pageCount(length);
    var i: usize = 0;
    while (i < pages) : (i += 1) {
        const byte: u8 = 1;
        protection.copyToUser(vec + i, &[_]u8{byte}) catch return abi.EFAULT;
    }
    return 0;
}

pub fn sys_getrlimit(resource: u32, rlim_ptr: usize) i32 {
    if (!isValidResource(resource)) return abi.EINVAL;
    if (!protection.verifyUserPointer(rlim_ptr, @sizeOf(Rlimit))) return abi.EFAULT;

    const proc = process.getEffectiveCurrent() orelse return abi.ESRCH;
    const rlim = proc.rlimits[resource];
    protection.copyToUser(rlim_ptr, std.mem.asBytes(&rlim)) catch return abi.EFAULT;
    return 0;
}

pub fn sys_setrlimit(resource: u32, rlim_ptr: usize) i32 {
    if (!isValidResource(resource)) return abi.EINVAL;
    if (!protection.verifyUserPointer(rlim_ptr, @sizeOf(Rlimit))) return abi.EFAULT;

    const proc = process.getEffectiveCurrent() orelse return abi.ESRCH;

    var rlim: Rlimit = undefined;
    protection.copyFromUser(std.mem.asBytes(&rlim), rlim_ptr) catch return abi.EFAULT;

    proc.rlimits[resource] = rlim;
    return 0;
}

pub fn sys_prlimit64(pid: i32, resource: u32, new_limit: usize, old_limit: usize) i32 {
    if (!isValidResource(resource)) return abi.EINVAL;

    const target_proc = if (pid == 0)
        process.getEffectiveCurrent() orelse return abi.ESRCH
    else blk: {
        if (pid < 0) return abi.EINVAL;
        break :blk process.getProcessByPid(@intCast(pid)) orelse return abi.ESRCH;
    };

    if (old_limit != 0) {
        if (!protection.verifyUserPointer(old_limit, @sizeOf(Rlimit))) return abi.EFAULT;
        const rlim = target_proc.rlimits[resource];
        protection.copyToUser(old_limit, std.mem.asBytes(&rlim)) catch return abi.EFAULT;
    }

    if (new_limit != 0) {
        if (!protection.verifyUserPointer(new_limit, @sizeOf(Rlimit))) return abi.EFAULT;
        var rlim: Rlimit = undefined;
        protection.copyFromUser(std.mem.asBytes(&rlim), new_limit) catch return abi.EFAULT;
        target_proc.rlimits[resource] = rlim;
    }

    return 0;
}

pub fn sys_mprotect(addr: usize, len: usize, prot: u32) i32 {
    const proc = process.getCurrentProcess() orelse return abi.ENOSYS;
    mmap.mprotect(proc, addr, len, prot) catch |err| {
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

fn isValidResource(resource: u32) bool {
    return resource < process.RLIMIT_COUNT;
}

fn pageCount(length: usize) usize {
    return (length + 4095) / 4096;
}
