pub const kernel = @import("kernel/boot/entry.zig");
pub const isr = @import("kernel/interrupts/isr.zig");
pub const panic = @import("kernel/utils/builtin.zig").panic;
const abi = @import("native/core/abi.zig");
const session_manager = @import("native/session/session_manager.zig");
const syscall_surface = @import("native/kernel_api/syscall_surface.zig");
const userspace_executor = @import("native/task/userspace_executor.zig");
const timer = @import("kernel/timer/timer.zig");

export fn kernel_main() void {
    kernel.kernelMain();
}

export fn syscall_handler(context: *anyopaque) callconv(.c) void {
    const frame: *isr.Registers = @ptrCast(@alignCast(context));
    const port = session_manager.kernelPort() orelse {
        frame.eax = @intFromEnum(abi.SyscallStatus.unavailable);
        frame.edx = 0;
        frame.ecx = @intFromEnum(abi.DenialReason.none);
        return;
    };

    const result = syscall_surface.dispatch(
        port,
        userspace_executor.activeTaskId(),
        timer.getTicks(),
        frame.eaxpenguinz0,
        frame.ebx,
        frame.ecx,
    );
    frame.eax = @intFromEnum(result.status);
    frame.edx = result.bytes_written;
    frame.ecx = @intFromEnum(result.denial_reason);
}

comptime {
    _ = isr;
}
