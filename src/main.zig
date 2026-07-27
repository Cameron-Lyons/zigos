pub const kernel = @import("kernel/boot/entry.zig");
pub const isr = @import("kernel/interrupts/isr.zig");
pub const panic = @import("kernel/utils/builtin.zig").panic;
pub const session_manager = if (config.isNativeProfile())
    @import("native/session/session_manager.zig")
else
    struct {};
pub const production_artifact_manifest = @import("production_artifact_manifest");
pub const storage_volume = @import("native/storage/storage_volume.zig");
const abi = @import("native/core/abi.zig");
const component_port = @import("native/kernel_api/component_port.zig");
const crypto_hash = @import("native/core/crypto_hash.zig");
const config = @import("kernel/config.zig");
const embedded_userspace_archive = @import("userspace_archive");
const syscall_surface = @import("native/kernel_api/syscall_surface.zig");
const userspace_executor = @import("native/task/userspace_executor.zig");
const timer = @import("kernel/timer/timer.zig");

pub const includes_verification_evidence = config.includesVerificationEvidence();

var published_kernel_port_addr: usize = 0;
var published_active_task_id: u64 = 0;

extern const __kernel_measure_start: u8;
extern const __kernel_measure_end: u8;

pub fn publishKernelPort(port: anytype) void {
    published_kernel_port_addr = @intFromPtr(port);
}

pub fn clearKernelPort() void {
    published_kernel_port_addr = 0;
}

pub fn publishUserspaceActiveTaskId(task_id: u64) void {
    published_active_task_id = task_id;
}

pub fn bootloaderMeasurementDigest() [32]u8 {
    var hasher = crypto_hash.init();
    crypto_hash.updateBytes(&hasher, "bootloader", "multiboot");
    crypto_hash.updateBytes(&hasher, "boot-profile", config.name());
    crypto_hash.updateBytes(&hasher, "entry-assembly", "src/boot/boot64.S");
    return crypto_hash.finalize(&hasher);
}

pub fn bootloaderSourceDigest() [32]u8 {
    var hasher = crypto_hash.init();
    hasher.update(@embedFile("boot/boot64.S"));
    return crypto_hash.finalize(&hasher);
}

pub fn kernelImageDigest() [32]u8 {
    const start = @intFromPtr(&__kernel_measure_start);
    const end = @intFromPtr(&__kernel_measure_end);
    var hasher = crypto_hash.init();
    crypto_hash.updateBytes(&hasher, "kernel-measured-region", @as([*]const u8, @ptrFromInt(start))[0 .. end - start]);
    return crypto_hash.finalize(&hasher);
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
    if (comptime config.isNativeProfile()) return session_manager.kernelPort();
    return null;
}

comptime {
    _ = isr;
    if (embedded_userspace_archive.includes_verification_images != config.includesVerificationEvidence()) {
        @compileError("kernel role and embedded userspace archive role must match");
    }
}
