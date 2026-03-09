const std = @import("std");

pub const BootProfile = enum {
    dev,
    ci_smoke,
    test_vm,
};

const KernelArtifact = struct {
    install_step: *std.Build.Step,
    output_path: []const u8,
};

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{
        .default_target = .{
            .cpu_arch = .x86,
            .os_tag = .freestanding,
            .abi = .none,
        },
    });

    const optimize = b.standardOptimizeOption(.{});

    const dev_kernel = addKernelArtifact(b, target, optimize, "kernel.elf", .dev);
    const ci_smoke_kernel = addKernelArtifact(b, target, optimize, "kernel-ci-smoke.elf", .ci_smoke);
    const vm_test_kernel = addKernelArtifact(b, target, optimize, "kernel-test-vm.elf", .test_vm);

    const kernel_step = b.step("kernel", "Build the development kernel");
    kernel_step.dependOn(dev_kernel.install_step);

    const ci_kernel_step = b.step("kernel-ci-smoke", "Build the CI smoke test kernel");
    ci_kernel_step.dependOn(ci_smoke_kernel.install_step);

    const vm_kernel_step = b.step("kernel-test-vm", "Build the VM test kernel");
    vm_kernel_step.dependOn(vm_test_kernel.install_step);

    const qemu_cmd = b.addSystemCommand(&.{
        "qemu-system-x86_64",
        "-kernel",
        dev_kernel.output_path,
        "-m",
        "256M",
        "-cpu",
        "qemu64",
        "-smp",
        "2",
        "-no-reboot",
        "-no-shutdown",
        "-device",
        "e1000,netdev=net0",
        "-netdev",
        "user,id=net0,dhcpstart=10.0.2.15",
        "-device",
        "AC97",
        "-drive",
        "file=disk.img,if=ide,format=raw,id=disk0",
    });
    qemu_cmd.step.dependOn(dev_kernel.install_step);

    const run_step = b.step("run", "Run the development kernel in QEMU");
    run_step.dependOn(&qemu_cmd.step);

    const ci_qemu_cmd = b.addSystemCommand(&.{
        "qemu-system-x86_64",
        "-kernel",
        ci_smoke_kernel.output_path,
        "-m",
        "128M",
        "-display",
        "none",
        "-serial",
        "stdio",
        "-monitor",
        "none",
        "-no-reboot",
        "-device",
        "isa-debug-exit,iobase=0xf4,iosize=0x04",
    });
    ci_qemu_cmd.step.dependOn(ci_smoke_kernel.install_step);
    ci_qemu_cmd.expectExitCode(33);

    const run_ci_step = b.step("run-ci-smoke", "Run the CI smoke kernel in QEMU");
    run_ci_step.dependOn(&ci_qemu_cmd.step);

    const vm_qemu_cmd = b.addSystemCommand(&.{
        "qemu-system-x86_64",
        "-kernel",
        vm_test_kernel.output_path,
        "-m",
        "128M",
        "-display",
        "none",
        "-serial",
        "stdio",
        "-monitor",
        "none",
        "-no-reboot",
        "-device",
        "isa-debug-exit,iobase=0xf4,iosize=0x04",
    });
    vm_qemu_cmd.step.dependOn(vm_test_kernel.install_step);
    vm_qemu_cmd.expectExitCode(33);

    const run_vm_step = b.step("run-test-vm", "Run the VM test kernel in QEMU");
    run_vm_step.dependOn(&vm_qemu_cmd.step);

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
        \\\"$GRUB_MKRESCUE" -o build/os.iso build/iso
    });
    iso_cmd.step.dependOn(dev_kernel.install_step);

    const iso_step = b.step("iso", "Build bootable ISO (requires GRUB mkrescue, xorriso, and mtools)");
    iso_step.dependOn(&iso_cmd.step);

    const boot_test_cmd = b.addSystemCommand(&.{
        "sh", "-c",
        \\set -eu
        \\QEMU_BIN="${QEMU_BIN:-qemu-system-x86_64}"
        \\BOOT_TEST_SECONDS="${BOOT_TEST_SECONDS:-12}"
        \\if ! command -v "$QEMU_BIN" >/dev/null 2>&1; then
        \\  echo "QEMU binary '$QEMU_BIN' not found. Set QEMU_BIN or install QEMU." >&2
        \\  exit 1
        \\fi
        \\mkdir -p build
        \\LOG_PATH="build/boot-test-serial.log"
        \\rm -f "$LOG_PATH"
        \\\"$QEMU_BIN" \\
        \\  -cdrom build/os.iso \\
        \\  -boot d \\
        \\  -m 256M \\
        \\  -display none \\
        \\  -serial file:"$LOG_PATH" \\
        \\  -monitor none \\
        \\  -no-reboot \\
        \\  -no-shutdown \\
        \\  >/dev/null 2>&1 &
        \\QEMU_PID=$!
        \\sleep "$BOOT_TEST_SECONDS"
        \\if kill -0 "$QEMU_PID" >/dev/null 2>&1; then
        \\  kill -TERM "$QEMU_PID" >/dev/null 2>&1 || true
        \\  sleep 1
        \\  kill -KILL "$QEMU_PID" >/dev/null 2>&1 || true
        \\fi
        \\wait "$QEMU_PID" >/dev/null 2>&1 || true
        \\if [ ! -s "$LOG_PATH" ]; then
        \\  echo "Boot test failed: no serial output at $LOG_PATH" >&2
        \\  exit 1
        \\fi
        \\if ! grep -q "Welcome to ZigOS" "$LOG_PATH"; then
        \\  echo "Boot test failed: missing marker 'Welcome to ZigOS'" >&2
        \\  cat "$LOG_PATH" >&2
        \\  exit 1
        \\fi
        \\if ! grep -q "A minimal operating system written in Zig" "$LOG_PATH"; then
        \\  echo "Boot test failed: missing marker 'A minimal operating system written in Zig'" >&2
        \\  cat "$LOG_PATH" >&2
        \\  exit 1
        \\fi
        \\if ! grep -q "Initializing GDT" "$LOG_PATH"; then
        \\  echo "Boot test failed: missing marker 'Initializing GDT'" >&2
        \\  cat "$LOG_PATH" >&2
        \\  exit 1
        \\fi
        \\WELCOME_LINE="$(grep -n "Welcome to ZigOS" "$LOG_PATH" | head -n1 | cut -d: -f1)"
        \\MINIMAL_LINE="$(grep -n "A minimal operating system written in Zig" "$LOG_PATH" | head -n1 | cut -d: -f1)"
        \\GDT_LINE="$(grep -n "Initializing GDT" "$LOG_PATH" | head -n1 | cut -d: -f1)"
        \\if [ "$MINIMAL_LINE" -le "$WELCOME_LINE" ] || [ "$GDT_LINE" -le "$MINIMAL_LINE" ]; then
        \\  echo "Boot test failed: boot markers are out of order" >&2
        \\  cat "$LOG_PATH" >&2
        \\  exit 1
        \\fi
        \\if grep -Eqi "panic|KERNEL PANIC|System Halted" "$LOG_PATH"; then
        \\  echo "Boot test failed: panic marker found in boot log" >&2
        \\  cat "$LOG_PATH" >&2
        \\  exit 1
        \\fi
        \\echo "Boot test passed. Log: $LOG_PATH"
    });
    boot_test_cmd.step.dependOn(&iso_cmd.step);

    const boot_test_step = b.step("boot-test", "Build ISO and verify headless boot markers in QEMU");
    boot_test_step.dependOn(&boot_test_cmd.step);
}

fn addKernelArtifact(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    name: []const u8,
    boot_profile: BootProfile,
) KernelArtifact {
    const options = b.addOptions();
    options.addOption(BootProfile, "boot_profile", boot_profile);

    const kernel_module = b.addModule(b.fmt("kernel-{s}", .{@tagName(boot_profile)}), .{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    kernel_module.addOptions("build_options", options);
    kernel_module.addAssemblyFile(b.path("src/boot/boot64.S"));
    kernel_module.addAssemblyFile(b.path("src/kernel/interrupts/interrupt32.S"));
    kernel_module.addAssemblyFile(b.path("src/kernel/interrupts/interrupts.s"));
    kernel_module.addAssemblyFile(b.path("src/kernel/interrupts/gdt_flush.S"));
    kernel_module.addAssemblyFile(b.path("src/kernel/process/context_switch.S"));

    const kernel = b.addExecutable(.{
        .name = name,
        .root_module = kernel_module,
    });
    kernel.setLinkerScript(b.path("src/arch/x86_64/linker.ld"));

    const install = b.addInstallArtifact(kernel, .{});
    return .{
        .install_step = &install.step,
        .output_path = b.fmt("zig-out/bin/{s}", .{name}),
    };
}
