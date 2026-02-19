const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{
        .default_target = .{
            .cpu_arch = .x86,
            .os_tag = .freestanding,
            .abi = .none,
        },
    });

    const optimize = b.standardOptimizeOption(.{});

    const kernel_module = b.addModule("kernel", .{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    
    const kernel = b.addExecutable(.{
        .name = "kernel.elf",
        .root_module = kernel_module,
    });

    kernel_module.addAssemblyFile(b.path("src/boot/boot64.S"));
    kernel_module.addAssemblyFile(b.path("src/kernel/interrupts/interrupt32.S"));
    kernel_module.addAssemblyFile(b.path("src/kernel/interrupts/interrupts.s"));
    kernel_module.addAssemblyFile(b.path("src/kernel/interrupts/gdt_flush.S"));
    kernel_module.addAssemblyFile(b.path("src/kernel/process/context_switch.S"));
    kernel.setLinkerScript(b.path("src/arch/x86_64/linker.ld"));

    b.installArtifact(kernel);

    const kernel_step = b.step("kernel", "Build the kernel");
    kernel_step.dependOn(&kernel.step);

    const qemu_cmd = b.addSystemCommand(&.{
        "qemu-system-x86_64",
        "-kernel",
        "zig-out/bin/kernel.elf",
        "-m",
        "128M",
        "-no-reboot",
        "-no-shutdown",
        "-append",
        "console=ttyS0",
    });
    qemu_cmd.step.dependOn(b.getInstallStep());

    const run_step = b.step("run", "Run the OS in QEMU");
    run_step.dependOn(&qemu_cmd.step);

    const iso_cmd = b.addSystemCommand(&.{
        "sh", "-c",
        \\set -eu
        \\GRUB_MKRESCUE="${GRUB_MKRESCUE:-}"
        \\if [ -z "$GRUB_MKRESCUE" ]; then
        \\  for cmd in grub-mkrescue i686-elf-grub-mkrescue x86_64-elf-grub-mkrescue; do
        \\    if command -v "$cmd" >/dev/null 2>&1; then
        \\      GRUB_MKRESCUE="$cmd"
        \\      break
        \\    fi
        \\  done
        \\fi
        \\if [ -z "$GRUB_MKRESCUE" ]; then
        \\  echo "No GRUB mkrescue command found. Set GRUB_MKRESCUE or install GRUB tools." >&2
        \\  exit 1
        \\fi
        \\if ! command -v xorriso >/dev/null 2>&1; then
        \\  echo "xorriso not found. Install xorriso." >&2
        \\  exit 1
        \\fi
        \\if ! command -v mformat >/dev/null 2>&1; then
        \\  echo "mformat not found. Install mtools." >&2
        \\  exit 1
        \\fi
        \\mkdir -p build/iso/boot/grub
        \\cp zig-out/bin/kernel.elf build/iso/boot/
        \\cp src/boot/grub.cfg build/iso/boot/grub/
        \\"$GRUB_MKRESCUE" -o build/os.iso build/iso
    });
    iso_cmd.step.dependOn(b.getInstallStep());

    const iso_step = b.step("iso", "Build bootable ISO (requires GRUB mkrescue, xorriso, and mtools)");
    iso_step.dependOn(&iso_cmd.step);
}
