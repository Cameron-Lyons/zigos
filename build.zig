const std = @import("std");

pub const BootProfile = enum {
    dev,
    ci_smoke,
    test_vm,
    userland_smoke,
};

const KernelArtifact = struct {
    compile_step: *std.Build.Step.Compile,
    install_step: *std.Build.Step,
    output_path: []const u8,
};

const UserProgramArtifact = struct {
    compile_step: *std.Build.Step.Compile,
    install_step: *std.Build.Step,
    emitted_bin: std.Build.LazyPath,
    output_path: []const u8,
};

const headless_qemu_runner = "scripts/run-headless-qemu.sh";
const rootfs_image_path = "build/disk.img";

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{
        .default_target = .{
            .cpu_arch = .x86,
            .os_tag = .freestanding,
            .abi = .none,
        },
    });

    const optimize = b.standardOptimizeOption(.{});

    const hello_program = addUserProgram(b, target, optimize, "hello", "user/bin/hello.zig");
    const echo_program = addUserProgram(b, target, optimize, "echo", "user/bin/echo.zig");
    const uname_program = addUserProgram(b, target, optimize, "uname", "user/bin/uname.zig");
    const cat_program = addUserProgram(b, target, optimize, "cat", "user/bin/cat.zig");
    const ls_program = addUserProgram(b, target, optimize, "ls", "user/bin/ls.zig");
    const sleep_program = addUserProgram(b, target, optimize, "sleep", "user/bin/sleep.zig");
    const motd_install = b.addInstallFileWithDir(b.path("user/rootfs/etc/motd"), .{ .custom = "user/rootfs/etc" }, "motd");
    const user_assets_module = createUserAssetsModule(b, target, optimize, hello_program, echo_program, uname_program, cat_program, ls_program);

    const dev_kernel = addKernelArtifact(b, target, optimize, "kernel.elf", .dev, user_assets_module);
    const ci_smoke_kernel = addKernelArtifact(b, target, optimize, "kernel-ci-smoke.elf", .ci_smoke, user_assets_module);
    const vm_test_kernel = addKernelArtifact(b, target, optimize, "kernel-test-vm.elf", .test_vm, user_assets_module);
    const userland_smoke_kernel = addKernelArtifact(b, target, optimize, "kernel-userland-smoke.elf", .userland_smoke, user_assets_module);

    const kernel_userland_dependencies = [_]*std.Build.Step{
        hello_program.install_step,
        echo_program.install_step,
        uname_program.install_step,
        cat_program.install_step,
        ls_program.install_step,
        sleep_program.install_step,
    };

    inline for (&.{ dev_kernel, ci_smoke_kernel, vm_test_kernel, userland_smoke_kernel }) |artifact| {
        for (kernel_userland_dependencies) |dependency| {
            artifact.compile_step.step.dependOn(dependency);
        }
    }

    const kernel_step = b.step("kernel", "Build the development kernel");
    kernel_step.dependOn(dev_kernel.install_step);

    const ci_kernel_step = b.step("kernel-ci-smoke", "Build the CI smoke test kernel");
    ci_kernel_step.dependOn(ci_smoke_kernel.install_step);

    const vm_kernel_step = b.step("kernel-test-vm", "Build the VM test kernel");
    vm_kernel_step.dependOn(vm_test_kernel.install_step);

    const userland_smoke_kernel_step = b.step("kernel-userland-smoke", "Build the userland smoke-test kernel");
    userland_smoke_kernel_step.dependOn(userland_smoke_kernel.install_step);

    const userland_step = b.step("userland", "Build the staged user programs");
    userland_step.dependOn(hello_program.install_step);
    userland_step.dependOn(echo_program.install_step);
    userland_step.dependOn(uname_program.install_step);
    userland_step.dependOn(cat_program.install_step);
    userland_step.dependOn(ls_program.install_step);
    userland_step.dependOn(sleep_program.install_step);
    userland_step.dependOn(&motd_install.step);

    const rootfs_cmd = b.addSystemCommand(&.{
        "sh", "-c",
        \\set -eu
        \\if ! command -v mkfs.fat >/dev/null 2>&1; then
        \\  echo "mkfs.fat not found. Install dosfstools." >&2
        \\  exit 1
        \\fi
        \\if ! command -v mmd >/dev/null 2>&1; then
        \\  echo "mmd not found. Install mtools." >&2
        \\  exit 1
        \\fi
        \\if ! command -v mcopy >/dev/null 2>&1; then
        \\  echo "mcopy not found. Install mtools." >&2
        \\  exit 1
        \\fi
        \\mkdir -p build
        \\rm -f "build/disk.img"
        \\truncate -s 64M "build/disk.img"
        \\mkfs.fat -F 32 "build/disk.img" >/dev/null
        \\mmd -i "build/disk.img" ::/etc
        \\mmd -i "build/disk.img" ::/bin
        \\mmd -i "build/disk.img" ::/tmp
        \\mmd -i "build/disk.img" ::/dev
        \\mmd -i "build/disk.img" ::/usr
        \\mmd -i "build/disk.img" ::/usr/bin
        \\mcopy -i "build/disk.img" "zig-out/user/bin/hello" ::/bin/hello
        \\mcopy -i "build/disk.img" "zig-out/user/bin/echo" ::/bin/echo
        \\mcopy -i "build/disk.img" "zig-out/user/bin/uname" ::/bin/uname
        \\mcopy -i "build/disk.img" "zig-out/user/bin/cat" ::/bin/cat
        \\mcopy -i "build/disk.img" "zig-out/user/bin/ls" ::/bin/ls
        \\mcopy -i "build/disk.img" "zig-out/user/bin/sleep" ::/bin/sleep
        \\mcopy -i "build/disk.img" "zig-out/user/rootfs/etc/motd" ::/etc/motd
    });
    rootfs_cmd.step.dependOn(hello_program.install_step);
    rootfs_cmd.step.dependOn(echo_program.install_step);
    rootfs_cmd.step.dependOn(uname_program.install_step);
    rootfs_cmd.step.dependOn(cat_program.install_step);
    rootfs_cmd.step.dependOn(ls_program.install_step);
    rootfs_cmd.step.dependOn(sleep_program.install_step);
    rootfs_cmd.step.dependOn(&motd_install.step);

    const rootfs_step = b.step("rootfs", "Build the FAT disk image for user programs");
    rootfs_step.dependOn(&rootfs_cmd.step);

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
        "file=" ++ rootfs_image_path ++ ",if=ide,format=raw,id=disk0",
    });
    qemu_cmd.step.dependOn(dev_kernel.install_step);
    qemu_cmd.step.dependOn(&rootfs_cmd.step);

    const run_step = b.step("run", "Run the development kernel in QEMU");
    run_step.dependOn(&qemu_cmd.step);

    const ci_qemu_cmd = b.addSystemCommand(&.{
        "bash",
        headless_qemu_runner,
        ci_smoke_kernel.output_path,
        "128M",
        "stdio",
    });
    ci_qemu_cmd.step.dependOn(ci_smoke_kernel.install_step);

    const run_ci_step = b.step("run-ci-smoke", "Run the CI smoke kernel in QEMU");
    run_ci_step.dependOn(&ci_qemu_cmd.step);

    const vm_qemu_cmd = b.addSystemCommand(&.{
        "bash",
        headless_qemu_runner,
        vm_test_kernel.output_path,
        "128M",
        "stdio",
    });
    vm_qemu_cmd.step.dependOn(vm_test_kernel.install_step);

    const run_vm_step = b.step("run-test-vm", "Run the VM test kernel in QEMU");
    run_vm_step.dependOn(&vm_qemu_cmd.step);

    const run_userland_smoke_cmd = b.addSystemCommand(&.{
        "qemu-system-x86_64",
        "-kernel",
        userland_smoke_kernel.output_path,
        "-m",
        "128M",
        "-display",
        "none",
        "-serial",
        "stdio",
        "-monitor",
        "none",
        "-no-reboot",
        "-no-shutdown",
        "-device",
        "isa-debug-exit,iobase=0xf4,iosize=0x04",
        "-drive",
        "file=" ++ rootfs_image_path ++ ",if=ide,format=raw,id=disk0",
    });
    run_userland_smoke_cmd.step.dependOn(userland_smoke_kernel.install_step);
    run_userland_smoke_cmd.step.dependOn(&rootfs_cmd.step);

    const run_userland_smoke_step = b.step("run-userland-smoke", "Run the userland smoke kernel in QEMU");
    run_userland_smoke_step.dependOn(&run_userland_smoke_cmd.step);

    const userland_smoke_test_cmd = b.addSystemCommand(&.{
        "sh", "-c",
        \\set -eu
        \\QEMU_BIN="${QEMU_BIN:-qemu-system-x86_64}"
        \\LOG_PATH="build/userland-smoke.log"
        \\if ! command -v "$QEMU_BIN" >/dev/null 2>&1; then
        \\  echo "QEMU binary '$QEMU_BIN' not found. Set QEMU_BIN or install QEMU." >&2
        \\  exit 1
        \\fi
        \\mkdir -p build
        \\rm -f "$LOG_PATH"
        \\USERLAND_SMOKE_SECONDS="${USERLAND_SMOKE_SECONDS:-10}"
        \\$QEMU_BIN -kernel "zig-out/bin/kernel-userland-smoke.elf" -m 128M -display none -serial file:"$LOG_PATH" -monitor none -no-reboot -no-shutdown -device isa-debug-exit,iobase=0xf4,iosize=0x04 -drive file="build/disk.img",if=ide,format=raw,id=disk0 >/dev/null 2>&1 &
        \\QEMU_PID=$!
        \\sleep "$USERLAND_SMOKE_SECONDS"
        \\if kill -0 "$QEMU_PID" >/dev/null 2>&1; then
        \\  kill -TERM "$QEMU_PID" >/dev/null 2>&1 || true
        \\  sleep 1
        \\  kill -KILL "$QEMU_PID" >/dev/null 2>&1 || true
        \\fi
        \\wait "$QEMU_PID" >/dev/null 2>&1 || true
        \\if [ ! -s "$LOG_PATH" ]; then
        \\  echo "Userland smoke test failed: no serial output captured" >&2
        \\  exit 1
        \\fi
        \\for marker in "BOOT:START" "BOOT:PROFILE:userland_smoke" "Disk root mounted at /" "BOOT:SHELL_READY" "USERLAND:HELLO" "USERLAND:ECHO" "USERLAND:ENV" "USERLAND:CMDSUB" "USERLAND:QUOTED" "USERLAND:ESCAPED" "USERLAND:GLOB" "USERLAND:UNAME" "USERLAND:LS" "USERLAND:CAT" "USERLAND:CD_BIN" "USERLAND:RELATIVE_CMD" "USERLAND:CD_ETC" "USERLAND:RELATIVE_ARG" "USERLAND:CD_ROOT" "USERLAND:PIPE_OK" "USERLAND:REDIRECT_WRITE" "USERLAND:REDIRECT_READ" "USERLAND:BG_START" "USERLAND:JOBS_RUNNING" "USERLAND:JOBS_STOPPED" "USERLAND:BG_RESUME" "USERLAND:JOBS_RESUMED" "user:root home:/home/user" "shell-ZigOS" "USERLAND QUOTED" "USERLAND ESCAPED" "/bin/cat /bin/ls" "USERLAND:RELATIVE" "Welcome to ZigOS userspace smoke test." "USERLAND:PIPE" "USERLAND:REDIRECT" "[1] Running /bin/sleep 3" "[1] Stopped /bin/sleep 3" "USERLAND:PASS"; do
        \\  if ! grep -Fq "$marker" "$LOG_PATH"; then
        \\    echo "Userland smoke test failed: missing marker '$marker'" >&2
        \\    cat "$LOG_PATH" >&2
        \\    exit 1
        \\  fi
        \\done
        \\if grep -Eqi "panic|KERNEL PANIC|System Halted|USERLAND:FAIL" "$LOG_PATH"; then
        \\  echo "Userland smoke test failed: panic or failure marker found" >&2
        \\  cat "$LOG_PATH" >&2
        \\  exit 1
        \\fi
        \\echo "Userland smoke test passed. Log: $LOG_PATH"
    });
    userland_smoke_test_cmd.step.dependOn(userland_smoke_kernel.install_step);
    userland_smoke_test_cmd.step.dependOn(&rootfs_cmd.step);

    const userland_smoke_test_step = b.step("userland-smoke-test", "Run the automated userland smoke test");
    userland_smoke_test_step.dependOn(&userland_smoke_test_cmd.step);

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
    user_assets_module: *std.Build.Module,
) KernelArtifact {
    const options = b.addOptions();
    options.addOption(BootProfile, "boot_profile", boot_profile);

    const kernel_module = b.addModule(b.fmt("kernel-{s}", .{@tagName(boot_profile)}), .{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    kernel_module.addOptions("build_options", options);
    kernel_module.addImport("user_assets", user_assets_module);
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
        .compile_step = kernel,
        .install_step = &install.step,
        .output_path = b.fmt("zig-out/bin/{s}", .{name}),
    };
}

fn createUserAssetsModule(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    hello_program: UserProgramArtifact,
    echo_program: UserProgramArtifact,
    uname_program: UserProgramArtifact,
    cat_program: UserProgramArtifact,
    ls_program: UserProgramArtifact,
) *std.Build.Module {
    const write_files = b.addWriteFiles();
    _ = write_files.addCopyFile(hello_program.emitted_bin, "assets/hello");
    _ = write_files.addCopyFile(echo_program.emitted_bin, "assets/echo");
    _ = write_files.addCopyFile(uname_program.emitted_bin, "assets/uname");
    _ = write_files.addCopyFile(cat_program.emitted_bin, "assets/cat");
    _ = write_files.addCopyFile(ls_program.emitted_bin, "assets/ls");
    _ = write_files.addCopyFile(b.path("user/rootfs/etc/motd"), "assets/motd");
    const assets_source = write_files.add("user_assets.zig", b.fmt(
        \\pub const hello = @embedFile("assets/hello");
        \\pub const echo = @embedFile("assets/echo");
        \\pub const uname = @embedFile("assets/uname");
        \\pub const cat = @embedFile("assets/cat");
        \\pub const ls = @embedFile("assets/ls");
        \\pub const motd = @embedFile("assets/motd");
    , .{}));

    return b.createModule(.{
        .root_source_file = assets_source,
        .target = target,
        .optimize = optimize,
    });
}

fn addUserProgram(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    name: []const u8,
    root_source: []const u8,
) UserProgramArtifact {
    _ = optimize;
    const user_optimize: std.builtin.OptimizeMode = .ReleaseSmall;

    const abi_module = b.createModule(.{
        .root_source_file = b.path("src/abi/syscall.zig"),
        .target = target,
        .optimize = user_optimize,
    });

    const syscall_module = b.createModule(.{
        .root_source_file = b.path("user/lib/syscall.zig"),
        .target = target,
        .optimize = user_optimize,
    });
    syscall_module.addImport("abi", abi_module);

    const runtime_module = b.createModule(.{
        .root_source_file = b.path("user/lib/runtime.zig"),
        .target = target,
        .optimize = user_optimize,
    });
    runtime_module.addImport("syscall", syscall_module);

    const cstr_module = b.createModule(.{
        .root_source_file = b.path("user/lib/cstr.zig"),
        .target = target,
        .optimize = user_optimize,
    });

    const stdio_module = b.createModule(.{
        .root_source_file = b.path("user/lib/stdio.zig"),
        .target = target,
        .optimize = user_optimize,
    });
    stdio_module.addImport("syscall", syscall_module);

    const user_module = b.addModule(b.fmt("user-{s}", .{name}), .{
        .root_source_file = b.path(root_source),
        .target = target,
        .optimize = user_optimize,
    });
    user_module.addImport("cstr", cstr_module);
    user_module.addImport("runtime", runtime_module);
    user_module.addImport("syscall", syscall_module);
    user_module.addImport("stdio", stdio_module);

    user_module.addAssemblyFile(b.path("user/crt0.S"));

    const program = b.addExecutable(.{
        .name = name,
        .root_module = user_module,
    });
    program.setLinkerScript(b.path("user/linker.ld"));

    const install = b.addInstallArtifact(program, .{
        .dest_dir = .{ .override = .{ .custom = "user/bin" } },
        .dest_sub_path = name,
    });

    return .{
        .compile_step = program,
        .install_step = &install.step,
        .emitted_bin = program.getEmittedBin(),
        .output_path = b.fmt("zig-out/user/bin/{s}", .{name}),
    };
}
