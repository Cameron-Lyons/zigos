const std = @import("std");
const abi = @import("abi.zig");
const protection = @import("../../memory/protection.zig");
const kernel_signal = @import("../signal.zig");

pub fn sys_kill(pid: i32, signum: i32) i32 {
    kernel_signal.kill(pid, signum) catch |err| {
        return switch (err) {
            error.InvalidSignal => abi.EINVAL,
            error.NoSuchProcess => abi.ESRCH,
        };
    };
    return 0;
}

pub fn sys_sigaction(signum: i32, act_addr: usize, oldact_addr: usize) i32 {
    var act: ?*const kernel_signal.SigAction = null;
    var oldact: ?*kernel_signal.SigAction = null;
    var act_buf: [@sizeOf(kernel_signal.SigAction)]u8 = undefined;
    var oldact_buf: kernel_signal.SigAction = undefined;

    if (act_addr != 0) {
        if (!protection.verifyUserPointer(act_addr, @sizeOf(kernel_signal.SigAction))) return abi.EINVAL;
        protection.copyFromUser(&act_buf, act_addr) catch return abi.EINVAL;
        act = @ptrCast(@alignCast(&act_buf));
    }

    if (oldact_addr != 0) {
        if (!protection.verifyUserPointer(oldact_addr, @sizeOf(kernel_signal.SigAction))) return abi.EINVAL;
        oldact = &oldact_buf;
    }

    kernel_signal.sigaction(signum, act, oldact) catch return abi.EINVAL;

    if (oldact_addr != 0) {
        protection.copyToUser(oldact_addr, std.mem.asBytes(&oldact_buf)) catch return abi.EINVAL;
    }

    return 0;
}

pub fn sys_sigprocmask(how: i32, set_addr: usize, oldset_addr: usize) i32 {
    var set_ptr: ?*const kernel_signal.SigSet = null;
    var oldset_ptr: ?*kernel_signal.SigSet = null;
    var set_buf: kernel_signal.SigSet = undefined;
    var oldset_buf: kernel_signal.SigSet = undefined;

    if (set_addr != 0) {
        if (!protection.verifyUserPointer(set_addr, @sizeOf(kernel_signal.SigSet))) return abi.EINVAL;
        protection.copyFromUser(std.mem.asBytes(&set_buf), set_addr) catch return abi.EINVAL;
        set_ptr = &set_buf;
    }

    if (oldset_addr != 0) {
        if (!protection.verifyUserPointer(oldset_addr, @sizeOf(kernel_signal.SigSet))) return abi.EINVAL;
        oldset_ptr = &oldset_buf;
    }

    kernel_signal.sigprocmask(how, set_ptr, oldset_ptr) catch return abi.EINVAL;

    if (oldset_addr != 0) {
        protection.copyToUser(oldset_addr, std.mem.asBytes(&oldset_buf)) catch return abi.EINVAL;
    }

    return 0;
}

pub fn sys_sigpending(set_addr: usize) i32 {
    if (!protection.verifyUserPointer(set_addr, @sizeOf(kernel_signal.SigSet))) return abi.EINVAL;

    var set: kernel_signal.SigSet = undefined;
    kernel_signal.sigpending(&set);

    protection.copyToUser(set_addr, std.mem.asBytes(&set)) catch return abi.EINVAL;
    return 0;
}

pub fn sys_sigsuspend(mask_addr: usize) i32 {
    if (!protection.verifyUserPointer(mask_addr, @sizeOf(kernel_signal.SigSet))) return abi.EINVAL;

    var mask: kernel_signal.SigSet = undefined;
    protection.copyFromUser(std.mem.asBytes(&mask), mask_addr) catch return abi.EINVAL;

    kernel_signal.sigsuspend(&mask) catch |err| {
        return switch (err) {
            error.Interrupted => abi.EINTR,
        };
    };
    return abi.EINTR;
}
