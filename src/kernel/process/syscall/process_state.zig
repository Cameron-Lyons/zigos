const std = @import("std");
const abi = @import("abi.zig");
const credentials = @import("../credentials.zig");
const process = @import("../process.zig");
const protection = @import("../../memory/protection.zig");
const signal = @import("../signal.zig");
const semantics = @import("syscall_semantics.zig");
const support = @import("support.zig");

var process_names: [support.PROCESS_SLOT_COUNT][support.PRCTL_NAME_SIZE]u8 =
    [_][support.PRCTL_NAME_SIZE]u8{[_]u8{0} ** support.PRCTL_NAME_SIZE} ** support.PROCESS_SLOT_COUNT;
var process_dumpable: [support.PROCESS_SLOT_COUNT]u32 = [_]u32{1} ** support.PROCESS_SLOT_COUNT;
var process_keepcaps: [support.PROCESS_SLOT_COUNT]u32 = [_]u32{0} ** support.PROCESS_SLOT_COUNT;
var process_pdeathsig: [support.PROCESS_SLOT_COUNT]u32 = [_]u32{0} ** support.PROCESS_SLOT_COUNT;
var process_priorities: [support.PROCESS_SLOT_COUNT]i32 = [_]i32{0} ** support.PROCESS_SLOT_COUNT;
var tid_addresses: [support.PROCESS_SLOT_COUNT]usize = [_]usize{0} ** support.PROCESS_SLOT_COUNT;
var robust_list_heads: [support.PROCESS_SLOT_COUNT]usize = [_]usize{0} ** support.PROCESS_SLOT_COUNT;
var robust_list_lens: [support.PROCESS_SLOT_COUNT]usize = [_]usize{0} ** support.PROCESS_SLOT_COUNT;

const SigInfo = extern struct {
    si_signo: i32,
    si_errno: i32,
    si_code: i32,
    si_pid: i32,
    si_uid: u32,
    si_status: i32,
    _pad: [26]i32,
};

pub fn sys_getgroups(size: i32, list_addr: usize) i32 {
    const proc = process.current_process orelse return abi.ESRCH;

    if (size == 0) {
        return @intCast(proc.creds.ngroups);
    }

    if (size < 0) return abi.EINVAL;
    const usize_size: usize = @intCast(size);
    if (!protection.verifyUserPointer(list_addr, usize_size * @sizeOf(u32))) return abi.EINVAL;

    const count: usize = @min(usize_size, proc.creds.ngroups);
    var groups: [credentials.MAX_GROUPS]u32 = undefined;
    for (0..count) |i| {
        groups[i] = proc.creds.groups[i];
    }

    protection.copyToUser(list_addr, std.mem.sliceAsBytes(groups[0..count])) catch return abi.EINVAL;
    return @intCast(count);
}

pub fn sys_setgroups(size: i32, list_addr: usize) i32 {
    const proc = process.current_process orelse return abi.ESRCH;
    if (!credentials.isRoot(&proc.creds)) return abi.EPERM;

    if (size < 0 or size > @as(i32, @intCast(credentials.MAX_GROUPS))) return abi.EINVAL;
    const usize_size: usize = @intCast(size);

    if (usize_size > 0) {
        if (!protection.verifyUserPointer(list_addr, usize_size * @sizeOf(u32))) return abi.EINVAL;
    }

    var groups: [credentials.MAX_GROUPS]u32 = undefined;
    if (usize_size > 0) {
        protection.copyFromUser(std.mem.sliceAsBytes(groups[0..usize_size]), list_addr) catch return abi.EINVAL;
    }

    for (0..usize_size) |i| {
        proc.creds.groups[i] = @intCast(groups[i]);
    }
    proc.creds.ngroups = @intCast(usize_size);

    return 0;
}

pub fn sys_prctl(option: u32, arg2: usize, arg3: usize, arg4: usize, arg5: usize) i32 {
    _ = arg4;
    _ = arg5;
    _ = arg3;

    const proc = process.current_process orelse return abi.ESRCH;
    const pid_idx = support.processMetadataSlot(proc.pid);

    switch (option) {
        abi.PR_SET_NAME => {
            if (!protection.verifyUserPointer(arg2, support.PRCTL_NAME_SIZE)) return abi.EFAULT;
            var name_buf: [support.PRCTL_NAME_SIZE]u8 = [_]u8{0} ** support.PRCTL_NAME_SIZE;
            protection.copyFromUser(&name_buf, arg2) catch return abi.EFAULT;
            process_names[pid_idx] = name_buf;
            return 0;
        },
        abi.PR_GET_NAME => {
            if (!protection.verifyUserPointer(arg2, support.PRCTL_NAME_SIZE)) return abi.EFAULT;
            protection.copyToUser(arg2, &process_names[pid_idx]) catch return abi.EFAULT;
            return 0;
        },
        abi.PR_SET_DUMPABLE => {
            if (arg2 > 2) return abi.EINVAL;
            process_dumpable[pid_idx] = @intCast(arg2);
            return 0;
        },
        abi.PR_GET_DUMPABLE => return @intCast(process_dumpable[pid_idx]),
        abi.PR_SET_KEEPCAPS => {
            process_keepcaps[pid_idx] = if (arg2 != 0) 1 else 0;
            return 0;
        },
        abi.PR_GET_KEEPCAPS => return @intCast(process_keepcaps[pid_idx]),
        abi.PR_SET_PDEATHSIG => {
            if (arg2 > support.MAX_SIGNAL_NUMBER) return abi.EINVAL;
            process_pdeathsig[pid_idx] = @intCast(arg2);
            return 0;
        },
        abi.PR_GET_PDEATHSIG => {
            if (!protection.verifyUserPointer(arg2, @sizeOf(i32))) return abi.EFAULT;
            const sig: i32 = @intCast(process_pdeathsig[pid_idx]);
            protection.copyToUser(arg2, std.mem.asBytes(&sig)) catch return abi.EFAULT;
            return 0;
        },
        else => return abi.EINVAL,
    }
}

pub fn sys_getpriority(which: u32, who: i32) i32 {
    switch (which) {
        abi.PRIO_PROCESS => {
            const pid: usize = if (who == 0) blk: {
                const proc = process.current_process orelse return abi.ESRCH;
                break :blk @intCast(proc.pid);
            } else @intCast(who);
            const pid_idx = support.processSlotFromPid(pid) orelse return abi.ESRCH;
            return semantics.userPriorityFromNice(process_priorities[pid_idx]);
        },
        abi.PRIO_PGRP, abi.PRIO_USER => return 20,
        else => return abi.EINVAL,
    }
}

pub fn sys_setpriority(which: u32, who: i32, prio: i32) i32 {
    const nice = semantics.clampNice(prio);

    switch (which) {
        abi.PRIO_PROCESS => {
            const pid: usize = if (who == 0) blk: {
                const proc = process.current_process orelse return abi.ESRCH;
                break :blk @intCast(proc.pid);
            } else @intCast(who);
            const pid_idx = support.processSlotFromPid(pid) orelse return abi.ESRCH;
            process_priorities[pid_idx] = nice;
            return 0;
        },
        abi.PRIO_PGRP, abi.PRIO_USER => return 0,
        else => return abi.EINVAL,
    }
}

pub fn sys_sched_getaffinity(pid: i32, cpusetsize: usize, mask_ptr: usize) i32 {
    _ = pid;
    if (!protection.verifyUserPointer(mask_ptr, cpusetsize)) return abi.EFAULT;

    var mask: [128]u8 = [_]u8{0} ** 128;
    mask[0] = 1;

    const copy_size = @min(cpusetsize, 128);
    protection.copyToUser(mask_ptr, mask[0..copy_size]) catch return abi.EFAULT;
    return @intCast(copy_size);
}

pub fn sys_sched_setaffinity(pid: i32, cpusetsize: usize, mask_ptr: usize) i32 {
    _ = pid;
    if (!protection.verifyUserPointer(mask_ptr, cpusetsize)) return abi.EFAULT;
    return 0;
}

pub fn sys_waitid(idtype: u32, id: i32, infop: usize, options: u32) i32 {
    _ = options;

    if (infop != 0) {
        if (!protection.verifyUserPointer(infop, @sizeOf(SigInfo))) return abi.EFAULT;
    }

    switch (idtype) {
        abi.P_ALL => {
            for (&process.process_table) |*proc| {
                if (proc.pid != 0 and (proc.state == .Zombie or proc.state == .Terminated)) {
                    if (infop != 0) {
                        var info = SigInfo{
                            .si_signo = signal.SIGCHLD,
                            .si_errno = 0,
                            .si_code = 1,
                            .si_pid = @intCast(proc.pid),
                            .si_uid = 0,
                            .si_status = proc.exit_code,
                            ._pad = [_]i32{0} ** 26,
                        };
                        protection.copyToUser(infop, std.mem.asBytes(&info)) catch return abi.EFAULT;
                    }
                    return 0;
                }
            }
            return abi.ECHILD;
        },
        abi.P_PID => {
            if (id < 0) return abi.EINVAL;
            const proc = process.getProcessByPid(@intCast(id)) orelse return abi.ECHILD;
            if (proc.state == .Zombie or proc.state == .Terminated) {
                if (infop != 0) {
                    var info = SigInfo{
                        .si_signo = signal.SIGCHLD,
                        .si_errno = 0,
                        .si_code = 1,
                        .si_pid = @intCast(proc.pid),
                        .si_uid = 0,
                        .si_status = proc.exit_code,
                        ._pad = [_]i32{0} ** 26,
                    };
                    protection.copyToUser(infop, std.mem.asBytes(&info)) catch return abi.EFAULT;
                }
                return 0;
            }
            return abi.ECHILD;
        },
        abi.P_PGID => return abi.ECHILD,
        else => return abi.EINVAL,
    }
}

pub fn sys_set_tid_address(tidptr: usize) i32 {
    const proc = process.current_process orelse return abi.ESRCH;
    const pid_idx = support.processMetadataSlot(proc.pid);
    tid_addresses[pid_idx] = tidptr;
    return @intCast(proc.pid);
}

pub fn sys_get_robust_list(pid: i32, head_ptr: usize, len_ptr: usize) i32 {
    if (!protection.verifyUserPointer(head_ptr, @sizeOf(usize))) return abi.EFAULT;
    if (!protection.verifyUserPointer(len_ptr, @sizeOf(usize))) return abi.EFAULT;

    const pid_idx: usize = if (pid == 0) blk: {
        const proc = process.current_process orelse return abi.ESRCH;
        break :blk @intCast(proc.pid);
    } else @intCast(pid);

    const slot = support.processSlotFromPid(pid_idx) orelse return abi.ESRCH;
    const head = robust_list_heads[slot];
    const len = robust_list_lens[slot];

    protection.copyToUser(head_ptr, std.mem.asBytes(&head)) catch return abi.EFAULT;
    protection.copyToUser(len_ptr, std.mem.asBytes(&len)) catch return abi.EFAULT;
    return 0;
}

pub fn sys_set_robust_list(head: usize, len: usize) i32 {
    const proc = process.current_process orelse return abi.ESRCH;
    const pid_idx = support.processMetadataSlot(proc.pid);

    robust_list_heads[pid_idx] = head;
    robust_list_lens[pid_idx] = len;
    return 0;
}

pub fn sys_tgkill(tgid: i32, tid: i32, sig: i32) i32 {
    _ = tgid;
    return sys_tkill(tid, sig);
}

pub fn sys_tkill(tid: i32, sig: i32) i32 {
    if (sig < 0 or sig > @as(i32, @intCast(support.MAX_SIGNAL_NUMBER))) return abi.EINVAL;
    if (tid < 0) return abi.EINVAL;

    const proc = process.getProcessByPid(@intCast(tid)) orelse return abi.ESRCH;
    if (sig == 0) return 0;

    signal.sendSignal(proc, @intCast(sig));
    return 0;
}
