pub const kernel = @import("kernel/boot/entry.zig");
pub const isr = @import("kernel/interrupts/isr.zig");
pub const panic = @import("kernel/utils/builtin.zig").panic;
pub const session_manager = @import("native/session/session_manager.zig");
pub const storage_volume = @import("native/storage/storage_volume.zig");
const abi = @import("native/core/abi.zig");
const component_port = @import("native/kernel_api/component_port.zig");
const syscall_surface = @import("native/kernel_api/syscall_surface.zig");
const userspace_executor = @import("native/task/userspace_executor.zig");
const timer = @import("kernel/timer/timer.zig");

var published_kernel_port_addr: usize = 0;
var published_active_task_id: u64 = 0;

pub fn publishKernelPort(port: anytype) void {
    published_kernel_port_addr = @intFromPtr(port);
}

pub fn clearKernelPort() void {
    published_kernel_port_addr = 0;
}

pub fn publishUserspaceActiveTaskId(task_id: u64) void {
    published_active_task_id = task_id;
}

export fn kernel_main() void {
    kernel.kernelMain();
}

export fn syscall_handler(context: *anyopaque) callconv(.c) void {
    const frame: *isr.Registers = @ptrCast(@alignCast(context));
    const port = currentKernelPort() orelse {
        frame.eax = @intFromEnum(abi.SyscallStatus.unavailable);
        frame.edx = 0;
        frame.ecx = @intFromEnum(abi.DenialReason.none);
        return;
    };
    const caller_task_id = if (published_active_task_id != 0)
        published_active_task_id
    else
        userspace_executor.activeTaskId();

    const result = syscall_surface.dispatch(
        port,
        caller_task_id,
        timer.getTicks(),
        frame.eax,
        frame.ebx,
        frame.ecx,
    );
    frame.eax = @intFromEnum(result.status);
    frame.edx = result.bytes_written;
    frame.ecx = @intFromEnum(result.denial_reason);
}

fn currentKernelPort() ?*component_port.KernelPort {
    if (published_kernel_port_addr != 0) return @ptrFromInt(published_kernel_port_addr);
    return session_manager.kernelPort();
}

comptime {
    _ = isr;
}
