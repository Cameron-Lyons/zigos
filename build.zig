const std = @import("std");
const shared = @import("build/shared.zig");
const programs = @import("build/programs.zig");
const kernel_build = @import("build/kernel.zig");
const userland_build = @import("build/userland.zig");
const rootfs_build = @import("build/rootfs.zig");
const qemu_build = @import("build/qemu.zig");

pub const BootProfile = shared.BootProfile;

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{
        .default_target = .{
            .cpu_arch = .x86,
            .os_tag = .freestanding,
            .abi = .none,
        },
    });

    const optimize = b.standardOptimizeOption(.{});
    const host_target = b.resolveTargetQuery(.{});
    const benchmark_optimize: std.builtin.OptimizeMode = if (optimize == .Debug) .ReleaseFast else optimize;

    var user_programs: [programs.user_program_specs.len]shared.UserProgramArtifact = undefined;
    inline for (programs.user_program_specs, 0..) |spec, i| {
        user_programs[i] = userland_build.addUserProgram(b, target, optimize, spec.name, spec.root_source);
    }

    const motd_install = b.addInstallFileWithDir(b.path("user/rootfs/etc/motd"), .{ .custom = "user/rootfs/etc" }, "motd");
    const passwd_install = b.addInstallFileWithDir(b.path("user/rootfs/etc/passwd"), .{ .custom = "user/rootfs/etc" }, "passwd");
    const user_assets_module = userland_build.createUserAssetsModule(b, target, optimize, programs.user_program_specs[0..], user_programs[0..]);

    const dev_kernel = kernel_build.addKernelArtifact(b, target, optimize, "kernel.elf", .dev, user_assets_module);
    const ci_smoke_kernel = kernel_build.addKernelArtifact(b, target, optimize, "kernel-ci-smoke.elf", .ci_smoke, user_assets_module);
    const vm_test_kernel = kernel_build.addKernelArtifact(b, target, optimize, "kernel-test-vm.elf", .test_vm, user_assets_module);
    const benchmark_kernel = kernel_build.addKernelArtifact(b, target, optimize, "kernel-benchmark.elf", .benchmark, user_assets_module);
    const smp_stress_kernel = kernel_build.addKernelArtifact(b, target, optimize, "kernel-smp-stress.elf", .smp_stress, user_assets_module);
    const userland_smoke_kernel = kernel_build.addKernelArtifact(b, target, optimize, "kernel-userland-smoke.elf", .userland_smoke, user_assets_module);
    const userland_sh_smoke_kernel = kernel_build.addKernelArtifact(b, target, optimize, "kernel-userland-sh-smoke.elf", .userland_sh_smoke, user_assets_module);

    inline for (&.{ dev_kernel, ci_smoke_kernel, vm_test_kernel, benchmark_kernel, smp_stress_kernel, userland_smoke_kernel, userland_sh_smoke_kernel }) |artifact| {
        userland_build.dependOnUserPrograms(&artifact.compile_step.step, user_programs[0..], &.{ &motd_install.step, &passwd_install.step });
    }

    const kernel_step = b.step("kernel", "Build the development kernel");
    kernel_step.dependOn(dev_kernel.install_step);

    const ci_kernel_step = b.step("kernel-ci-smoke", "Build the CI smoke test kernel");
    ci_kernel_step.dependOn(ci_smoke_kernel.install_step);

    const vm_kernel_step = b.step("kernel-test-vm", "Build the VM test kernel");
    vm_kernel_step.dependOn(vm_test_kernel.install_step);

    const benchmark_kernel_step = b.step("kernel-bench", "Build the kernel benchmark profile");
    benchmark_kernel_step.dependOn(benchmark_kernel.install_step);

    const smp_stress_kernel_step = b.step("kernel-smp-stress", "Build the SMP stress kernel profile");
    smp_stress_kernel_step.dependOn(smp_stress_kernel.install_step);

    const userland_smoke_kernel_step = b.step("kernel-userland-smoke", "Build the userland smoke-test kernel");
    userland_smoke_kernel_step.dependOn(userland_smoke_kernel.install_step);

    const userland_sh_smoke_kernel_step = b.step("kernel-userland-sh-smoke", "Build the userland sh smoke-test kernel");
    userland_sh_smoke_kernel_step.dependOn(userland_sh_smoke_kernel.install_step);

    const userland_step = b.step("userland", "Build the staged user programs");
    userland_build.dependOnUserPrograms(userland_step, user_programs[0..], &.{ &motd_install.step, &passwd_install.step });

    const rootfs_cmd = rootfs_build.addRootfsCommand(b);
    userland_build.dependOnUserPrograms(&rootfs_cmd.step, user_programs[0..], &.{ &motd_install.step, &passwd_install.step });

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
        "file=" ++ shared.rootfs_image_path ++ ",if=ide,format=raw,id=disk0",
    });
    qemu_cmd.step.dependOn(dev_kernel.install_step);
    qemu_cmd.step.dependOn(&rootfs_cmd.step);

    const run_step = b.step("run", "Run the development kernel in QEMU");
    run_step.dependOn(&qemu_cmd.step);

    const ci_qemu_cmd = qemu_build.addHeadlessRunner(b, ci_smoke_kernel.output_path, "128M", "stdio");
    ci_qemu_cmd.step.dependOn(ci_smoke_kernel.install_step);

    const run_ci_step = b.step("run-ci-smoke", "Run the CI smoke kernel in QEMU");
    run_ci_step.dependOn(&ci_qemu_cmd.step);

    const vm_qemu_cmd = qemu_build.addHeadlessRunner(b, vm_test_kernel.output_path, "128M", "stdio");
    vm_qemu_cmd.step.dependOn(vm_test_kernel.install_step);

    const run_vm_step = b.step("run-test-vm", "Run the VM test kernel in QEMU");
    run_vm_step.dependOn(&vm_qemu_cmd.step);

    const benchmark_qemu_cmd = qemu_build.addHeadlessRunner(b, benchmark_kernel.output_path, "128M", "stdio");
    benchmark_qemu_cmd.step.dependOn(benchmark_kernel.install_step);

    const run_benchmark_step = b.step("run-kernel-bench", "Run the kernel benchmark profile in QEMU");
    run_benchmark_step.dependOn(&benchmark_qemu_cmd.step);

    const run_smp_stress_cmd = b.addSystemCommand(&.{
        "sh",
        "-c",
        \\QEMU_EXTRA_ARGS="-cpu qemu64 -smp 2" bash scripts/run-headless-qemu.sh "zig-out/bin/kernel-smp-stress.elf" "256M" "stdio"
    });
    run_smp_stress_cmd.step.dependOn(smp_stress_kernel.install_step);

    const run_smp_stress_step = b.step("run-smp-stress", "Run the SMP stress kernel profile in QEMU");
    run_smp_stress_step.dependOn(&run_smp_stress_cmd.step);

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
        "file=" ++ shared.rootfs_image_path ++ ",if=ide,format=raw,id=disk0",
    });
    run_userland_smoke_cmd.step.dependOn(userland_smoke_kernel.install_step);
    run_userland_smoke_cmd.step.dependOn(&rootfs_cmd.step);

    const run_userland_smoke_step = b.step("run-userland-smoke", "Run the userland smoke kernel in QEMU");
    run_userland_smoke_step.dependOn(&run_userland_smoke_cmd.step);

    const run_userland_sh_smoke_cmd = b.addSystemCommand(&.{
        "qemu-system-x86_64",
        "-kernel",
        userland_sh_smoke_kernel.output_path,
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
        "file=" ++ shared.rootfs_image_path ++ ",if=ide,format=raw,id=disk0",
    });
    run_userland_sh_smoke_cmd.step.dependOn(userland_sh_smoke_kernel.install_step);
    run_userland_sh_smoke_cmd.step.dependOn(&rootfs_cmd.step);

    const run_userland_sh_smoke_step = b.step("run-userland-sh-smoke", "Run the focused /bin/sh smoke kernel in QEMU");
    run_userland_sh_smoke_step.dependOn(&run_userland_sh_smoke_cmd.step);

    const userland_smoke_test_cmd = b.addSystemCommand(&.{
        "bash",
        "scripts/run-userland-smoke.sh",
        userland_smoke_kernel.output_path,
        shared.rootfs_image_path,
        "build/userland-smoke.log",
        "build/userland-smoke-rootfs.txt",
    });
    userland_smoke_test_cmd.step.dependOn(userland_smoke_kernel.install_step);
    userland_smoke_test_cmd.step.dependOn(&rootfs_cmd.step);

    const userland_smoke_test_step = b.step("userland-smoke-test", "Run the automated userland smoke test");
    userland_smoke_test_step.dependOn(&userland_smoke_test_cmd.step);

    const userland_sh_smoke_test_cmd = b.addSystemCommand(&.{
        "bash",
        "scripts/run-userland-sh-smoke.sh",
        userland_sh_smoke_kernel.output_path,
        shared.rootfs_image_path,
        "build/userland-sh-smoke.log",
        "build/userland-sh-smoke-rootfs.txt",
    });
    userland_sh_smoke_test_cmd.step.dependOn(userland_sh_smoke_kernel.install_step);
    userland_sh_smoke_test_cmd.step.dependOn(&rootfs_cmd.step);

    const userland_sh_smoke_test_step = b.step("userland-sh-smoke-test", "Run the focused /bin/sh smoke test");
    userland_sh_smoke_test_step.dependOn(&userland_sh_smoke_test_cmd.step);

    const kernel_benchmark_test_cmd = b.addSystemCommand(&.{
        "bash",
        "scripts/run-kernel-benchmark.sh",
        benchmark_kernel.output_path,
        "build/kernel-benchmark.log",
    });
    kernel_benchmark_test_cmd.step.dependOn(benchmark_kernel.install_step);

    const kernel_benchmark_test_step = b.step("kernel-bench-test", "Run the automated kernel benchmark profile in QEMU");
    kernel_benchmark_test_step.dependOn(&kernel_benchmark_test_cmd.step);

    const smp_stress_test_cmd = b.addSystemCommand(&.{
        "bash",
        "scripts/run-smp-stress.sh",
        smp_stress_kernel.output_path,
        "build/smp-stress.log",
    });
    smp_stress_test_cmd.step.dependOn(smp_stress_kernel.install_step);

    const smp_stress_test_step = b.step("smp-stress-test", "Run the automated SMP scheduler stress profile in QEMU");
    smp_stress_test_step.dependOn(&smp_stress_test_cmd.step);

    const host_tests_cmd = b.addSystemCommand(&.{
        "sh",
        "-c",
        \\set -eu
        \\mkdir -p build/zig-cache-tests build/zig-global-cache-tests
        \\export ZIG_LOCAL_CACHE_DIR="build/zig-cache-tests"
        \\export ZIG_GLOBAL_CACHE_DIR="build/zig-global-cache-tests"
        \\for test_file in \
        \\  src/kernel/process/syscall/at_semantics.zig \
        \\  src/kernel/process/syscall/syscall_semantics.zig \
        \\  src/kernel/process/syscall/path_semantics.zig \
        \\  src/kernel/fs/fd_freelist.zig \
        \\  src/kernel/shell/parser/pipeline.zig \
        \\  src/kernel/shell/glob.zig \
        \\  src/kernel/shell/jobs.zig \
        \\  src/kernel/process/scheduler_policy.zig \
        \\  src/kernel/net/tcp/protocol.zig \
        \\  src/kernel/process/syscall/ipc_semantics.zig
        \\do
        \\  zig test "$test_file"
        \\done
    });
    const host_tests_step = b.step("host-tests", "Run host-side unit tests for extracted pure logic");
    host_tests_step.dependOn(&host_tests_cmd.step);

    const benchmark_module = kernel_build.createHostModule(b, host_target, benchmark_optimize, "src/benchmarks/main.zig");
    benchmark_module.addImport("at_semantics", kernel_build.createHostModule(b, host_target, benchmark_optimize, "src/kernel/process/syscall/at_semantics.zig"));
    benchmark_module.addImport("fd_freelist", kernel_build.createHostModule(b, host_target, benchmark_optimize, "src/kernel/fs/fd_freelist.zig"));
    benchmark_module.addImport("ipc_semantics", kernel_build.createHostModule(b, host_target, benchmark_optimize, "src/kernel/process/syscall/ipc_semantics.zig"));
    benchmark_module.addImport("shell_support", kernel_build.createHostModule(b, host_target, benchmark_optimize, "src/kernel/shell/bench_support.zig"));
    benchmark_module.addImport("tcp_protocol", kernel_build.createHostModule(b, host_target, benchmark_optimize, "src/kernel/net/tcp/protocol.zig"));

    const benchmark_exe = b.addExecutable(.{
        .name = "host-benchmarks",
        .root_module = benchmark_module,
    });
    const benchmark_run = b.addRunArtifact(benchmark_exe);
    if (b.args) |args| {
        benchmark_run.addArgs(args);
    }

    const benchmark_step = b.step("bench", "Run host-side benchmarks for extracted kernel logic");
    benchmark_step.dependOn(&benchmark_run.step);

    const iso_cmd = b.addSystemCommand(&.{
        "bash",
        "scripts/build-grub-iso.sh",
        dev_kernel.output_path,
        "build/os.iso",
        "build/iso",
    });
    iso_cmd.step.dependOn(dev_kernel.install_step);

    const iso_step = b.step("iso", "Build bootable ISO (requires GRUB mkrescue, xorriso, and mtools)");
    iso_step.dependOn(&iso_cmd.step);

    const boot_test_iso_cmd = b.addSystemCommand(&.{
        "bash",
        "scripts/build-grub-iso.sh",
        ci_smoke_kernel.output_path,
        "build/boot-test.iso",
        "build/boot-test-iso",
    });
    boot_test_iso_cmd.step.dependOn(ci_smoke_kernel.install_step);

    const boot_test_cmd = b.addSystemCommand(&.{
        "bash",
        "scripts/run-boot-test.sh",
        "build/boot-test.iso",
        "build/boot-test-serial.log",
    });
    boot_test_cmd.step.dependOn(&boot_test_iso_cmd.step);

    const boot_test_step = b.step("boot-test", "Build a CI-smoke ISO and verify headless boot markers in QEMU");
    boot_test_step.dependOn(&boot_test_cmd.step);
}
