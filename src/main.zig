pub const kernel = @import("kernel/boot/entry.zig");
pub const isr = @import("kernel/interrupts/isr.zig");
pub const panic = @import("kernel/utils/builtin.zig").panic;
pub const kernel_memory = @import("kernel/memory/memory.zig");
pub const session_manager = if (config.isNativeProfile())
    @import("native/session/session_manager.zig")
else
    struct {};
pub const production_artifact_manifest = @import("production_artifact_manifest");
const abi = @import("native/core/abi.zig");
const component_port = @import("native/kernel_api/component_port.zig");
const crypto_hash = @import("native/core/crypto_hash.zig");
const config = @import("kernel/config.zig");
const embedded_userspace_archive = @import("userspace_archive");
const syscall_cpu = @import("kernel/interrupts/syscall64.zig");
const endpoint_syscalls = @import("native/kernel_api/endpoint_syscalls.zig");
const syscall_surface = @import("native/kernel_api/syscall_surface.zig");
const userspace_executor = @import("native/task/userspace_executor.zig");
const timer = @import("kernel/timer/timer.zig");

pub const includes_verification_evidence = config.includesVerificationEvidence();

extern const __kernel_measure_start: u8;
extern const __kernel_measure_end: u8;

pub fn publishKernelPort(port: anytype) void {
    syscall_cpu.setKernelPort(@intFromPtr(port));
}

pub fn clearKernelPort() void {
    syscall_cpu.clearKernelPort();
}

pub fn publishUserspaceActiveTaskId(task_id: u64) void {
    syscall_cpu.setActiveTaskId(task_id);
}

pub fn bootloaderMeasurementDigest() [32]u8 {
    var hasher = crypto_hash.init();
    crypto_hash.updateBytes(&hasher, "bootloader", "efi");
    crypto_hash.updateBytes(&hasher, "boot-profile", config.name());
    crypto_hash.updateBytes(&hasher, "entry-assembly", bootloaderSourcePath());
    return crypto_hash.finalize(&hasher);
}

pub fn bootloaderSourceDigest() [32]u8 {
    var hasher = crypto_hash.init();
    hasher.update(@embedFile("boot/efi_stub.zig"));
    return crypto_hash.finalize(&hasher);
}

pub fn bootloaderSourcePath() []const u8 {
    return "src/boot/efi_stub.zig";
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
        frame.r10 = @intFromEnum(abi.DenialReason.none);
        return;
    };
    const caller_task_id = blk: {
        const published = syscall_cpu.currentActiveTaskId();
        if (published != 0) break :blk published;
        break :blk userspace_executor.activeTaskId();
    };

    if (endpoint_syscalls.dispatchRegister(
        port,
        caller_task_id,
        timer.getTicks(),
        .{
            .eax = frame.eax,
            .edx = frame.edx,
            .esi = frame.esi,
            .r8 = frame.r8,
            .r9 = frame.r9,
            .r10 = frame.r10,
            .r14 = frame.r14,
            .r15 = frame.r15,
        },
    )) |reply| {
        frame.eax = @intFromEnum(reply.status);
        frame.edx = reply.bytes_written;
        frame.r10 = @intFromEnum(reply.denial_reason);
        frame.r8 = reply.attached_slot;
        frame.edi = reply.correlation_id;
        frame.esi = reply.word0;
        frame.r14 = reply.word1;
        frame.r15 = reply.word2;
        return;
    }

    const result = syscall_surface.dispatch(
        port,
        caller_task_id,
        timer.getTicks(),
        @truncate(frame.eax),
        frame.edi,
        frame.esi,
        frame.edx,
    );
    frame.eax = @intFromEnum(result.status);
    frame.edx = result.bytes_written;
    frame.r10 = @intFromEnum(result.denial_reason);
}

fn currentKernelPort() ?*component_port.KernelPort {
    const published = syscall_cpu.currentKernelPortAddr();
    if (published != 0) return @ptrFromInt(published);
    return null;
}

comptime {
    _ = isr;
    if (embedded_userspace_archive.includes_verification_images != config.includesVerificationEvidence()) {
        @compileError("kernel role and embedded userspace archive role must match");
    }
}
