const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{
        .default_target = .{
            .cpu_arch = .x86_64,
            .os_tag = .freestanding,
            .abi = .none,
        },
    });

    const optimize = b.standardOptimizeOption(.{});

    const kernel = b.addExecutable(.{
        .name = "kernel.elf",
        .root_source_file = b.path("src/kernel/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    kernel.setLinkerScript(b.path("src/arch/x86_64/linker.ld"));

    b.installArtifact(kernel);

    const kernel_step = b.step("kernel", "Build the kernel");
    kernel_step.dependOn(&kernel.step);

    // Simple QEMU run without ISO for now
    const qemu_cmd = b.addSystemCommand(&.{
        "qemu-system-x86_64",
        "-kernel", "zig-out/bin/kernel.elf",
        "-m", "128M",
        "-no-reboot",
        "-no-shutdown",
        "-serial", "stdio",
    });
    qemu_cmd.step.dependOn(b.getInstallStep());

    const run_step = b.step("run", "Run the OS in QEMU");
    run_step.dependOn(&qemu_cmd.step);

    // ISO build step (requires grub-mkrescue)
    const iso_cmd = b.addSystemCommand(&.{
        "sh", "-c",
        \\mkdir -p build/iso/boot/grub &&
        \\cp zig-out/bin/kernel.elf build/iso/boot/ &&
        \\cp src/boot/grub.cfg build/iso/boot/grub/ &&
        \\grub-mkrescue -o build/os.iso build/iso
    });
    iso_cmd.step.dependOn(b.getInstallStep());

    const iso_step = b.step("iso", "Build bootable ISO (requires grub-mkrescue)");
    iso_step.dependOn(&iso_cmd.step);
}