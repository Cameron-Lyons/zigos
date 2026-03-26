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
    const vm_core_regression_kernel = kernel_build.addKernelArtifact(b, target, optimize, "kernel-vm-core-regression.elf", .vm_core_regression, user_assets_module);
    const vm_readiness_regression_kernel = kernel_build.addKernelArtifact(b, target, optimize, "kernel-vm-readiness-regression.elf", .vm_readiness_regression, user_assets_module);
    const vm_memory_regression_kernel = kernel_build.addKernelArtifact(b, target, optimize, "kernel-vm-memory-regression.elf", .vm_memory_regression, user_assets_module);
    const vm_state_regression_kernel = kernel_build.addKernelArtifact(b, target, optimize, "kernel-vm-state-regression.elf", .vm_state_regression, user_assets_module);
    const vm_tty_regression_kernel = kernel_build.addKernelArtifact(b, target, optimize, "kernel-vm-tty-regression.elf", .vm_tty_regression, user_assets_module);
    const vm_socket_regression_kernel = kernel_build.addKernelArtifact(b, target, optimize, "kernel-vm-socket-regression.elf", .vm_socket_regression, user_assets_module);
    const vm_event_regression_kernel = kernel_build.addKernelArtifact(b, target, optimize, "kernel-vm-event-regression.elf", .vm_event_regression, user_assets_module);
    const vm_inotify_regression_kernel = kernel_build.addKernelArtifact(b, target, optimize, "kernel-vm-inotify-regression.elf", .vm_inotify_regression, user_assets_module);
    const benchmark_kernel = kernel_build.addKernelArtifact(b, target, optimize, "kernel-benchmark.elf", .benchmark, user_assets_module);
    const smp_stress_kernel = kernel_build.addKernelArtifact(b, target, optimize, "kernel-smp-stress.elf", .smp_stress, user_assets_module);
    const smp_regression_kernel = kernel_build.addKernelArtifact(b, target, optimize, "kernel-smp-regression.elf", .smp_regression, user_assets_module);
    const manual_regression_kernel = kernel_build.addKernelArtifact(b, target, optimize, "kernel-manual-regression.elf", .manual_regression, user_assets_module);
    const ext2_regression_kernel = kernel_build.addKernelArtifact(b, target, optimize, "kernel-ext2-regression.elf", .ext2_regression, user_assets_module);
    const service_regression_kernel = kernel_build.addKernelArtifact(b, target, optimize, "kernel-service-regression.elf", .service_regression, user_assets_module);
    const scheduler_regression_kernel = kernel_build.addKernelArtifact(b, target, optimize, "kernel-scheduler-regression.elf", .scheduler_regression, user_assets_module);
    const nic_ingress_kernel = kernel_build.addKernelArtifact(b, target, optimize, "kernel-nic-ingress.elf", .nic_ingress, user_assets_module);
    const e1000_ingress_kernel = kernel_build.addKernelArtifact(b, target, optimize, "kernel-e1000-ingress.elf", .e1000_ingress, user_assets_module);
    const virtio_ingress_kernel = kernel_build.addKernelArtifact(b, target, optimize, "kernel-virtio-ingress.elf", .virtio_ingress, user_assets_module);
    const userland_smoke_kernel = kernel_build.addKernelArtifact(b, target, optimize, "kernel-userland-smoke.elf", .userland_smoke, user_assets_module);
    const userland_sh_smoke_kernel = kernel_build.addKernelArtifact(b, target, optimize, "kernel-userland-sh-smoke.elf", .userland_sh_smoke, user_assets_module);

    inline for (&.{ dev_kernel, ci_smoke_kernel, vm_test_kernel, vm_core_regression_kernel, vm_readiness_regression_kernel, vm_memory_regression_kernel, vm_state_regression_kernel, vm_tty_regression_kernel, vm_socket_regression_kernel, vm_event_regression_kernel, vm_inotify_regression_kernel, benchmark_kernel, smp_stress_kernel, smp_regression_kernel, manual_regression_kernel, ext2_regression_kernel, service_regression_kernel, scheduler_regression_kernel, nic_ingress_kernel, e1000_ingress_kernel, virtio_ingress_kernel, userland_smoke_kernel, userland_sh_smoke_kernel }) |artifact| {
        userland_build.dependOnUserPrograms(&artifact.compile_step.step, user_programs[0..], &.{ &motd_install.step, &passwd_install.step });
    }

    const kernel_step = b.step("kernel", "Build the development kernel");
    kernel_step.dependOn(dev_kernel.install_step);

    const ci_kernel_step = b.step("kernel-ci-smoke", "Build the CI smoke test kernel");
    ci_kernel_step.dependOn(ci_smoke_kernel.install_step);

    const vm_kernel_step = b.step("kernel-test-vm", "Build the VM test kernel");
    vm_kernel_step.dependOn(vm_test_kernel.install_step);

    const vm_core_regression_kernel_step = b.step("kernel-vm-core-regression", "Build the VM core regression kernel");
    vm_core_regression_kernel_step.dependOn(vm_core_regression_kernel.install_step);

    const vm_readiness_regression_kernel_step = b.step("kernel-vm-readiness-regression", "Build the VM readiness regression kernel");
    vm_readiness_regression_kernel_step.dependOn(vm_readiness_regression_kernel.install_step);

    const vm_memory_regression_kernel_step = b.step("kernel-vm-memory-regression", "Build the VM memory regression kernel");
    vm_memory_regression_kernel_step.dependOn(vm_memory_regression_kernel.install_step);

    const vm_state_regression_kernel_step = b.step("kernel-vm-state-regression", "Build the VM state regression kernel");
    vm_state_regression_kernel_step.dependOn(vm_state_regression_kernel.install_step);

    const vm_tty_regression_kernel_step = b.step("kernel-vm-tty-regression", "Build the VM tty regression kernel");
    vm_tty_regression_kernel_step.dependOn(vm_tty_regression_kernel.install_step);

    const vm_socket_regression_kernel_step = b.step("kernel-vm-socket-regression", "Build the VM socket regression kernel");
    vm_socket_regression_kernel_step.dependOn(vm_socket_regression_kernel.install_step);

    const vm_event_regression_kernel_step = b.step("kernel-vm-event-regression", "Build the VM event regression kernel");
    vm_event_regression_kernel_step.dependOn(vm_event_regression_kernel.install_step);

    const vm_inotify_regression_kernel_step = b.step("kernel-vm-inotify-regression", "Build the VM inotify regression kernel");
    vm_inotify_regression_kernel_step.dependOn(vm_inotify_regression_kernel.install_step);

    const benchmark_kernel_step = b.step("kernel-bench", "Build the kernel benchmark profile");
    benchmark_kernel_step.dependOn(benchmark_kernel.install_step);

    const smp_stress_kernel_step = b.step("kernel-smp-stress", "Build the SMP stress kernel profile");
    smp_stress_kernel_step.dependOn(smp_stress_kernel.install_step);

    const smp_regression_kernel_step = b.step("kernel-smp-regression", "Build the SMP regression kernel profile");
    smp_regression_kernel_step.dependOn(smp_regression_kernel.install_step);

    const manual_regression_kernel_step = b.step("kernel-manual-regression", "Build the manual regression kernel profile");
    manual_regression_kernel_step.dependOn(manual_regression_kernel.install_step);

    const ext2_regression_kernel_step = b.step("kernel-ext2-regression", "Build the ext2 regression kernel profile");
    ext2_regression_kernel_step.dependOn(ext2_regression_kernel.install_step);

    const service_regression_kernel_step = b.step("kernel-service-regression", "Build the service regression kernel profile");
    service_regression_kernel_step.dependOn(service_regression_kernel.install_step);

    const scheduler_regression_kernel_step = b.step("kernel-scheduler-regression", "Build the scheduler regression kernel profile");
    scheduler_regression_kernel_step.dependOn(scheduler_regression_kernel.install_step);

    const nic_ingress_kernel_step = b.step("kernel-nic-ingress", "Build the NIC ingress regression kernel profile");
    nic_ingress_kernel_step.dependOn(nic_ingress_kernel.install_step);

    const e1000_ingress_kernel_step = b.step("kernel-e1000-ingress", "Build the E1000 ingress regression kernel profile");
    e1000_ingress_kernel_step.dependOn(e1000_ingress_kernel.install_step);

    const virtio_ingress_kernel_step = b.step("kernel-virtio-ingress", "Build the VirtIO ingress regression kernel profile");
    virtio_ingress_kernel_step.dependOn(virtio_ingress_kernel.install_step);

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

    const ext2_image_cmd = b.addSystemCommand(&.{
        "bash",
        "scripts/build-ext2-image.sh",
        "build/ext2.img",
    });

    const ext2_image_step = b.step("ext2-image", "Build the ext2 disk image for regression tests");
    ext2_image_step.dependOn(&ext2_image_cmd.step);

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

    const vm_core_regression_test_cmd = b.addSystemCommand(&.{
        "bash",
        "scripts/run-vm-regression.sh",
        vm_core_regression_kernel.output_path,
        "vm_core_regression",
        "VMCORE",
        "build/vm-core-regression.log",
    });
    vm_core_regression_test_cmd.step.dependOn(vm_core_regression_kernel.install_step);

    const vm_core_regression_test_step = b.step("vm-core-regression-test", "Run the VM core regression profile in QEMU");
    vm_core_regression_test_step.dependOn(&vm_core_regression_test_cmd.step);

    const vm_readiness_regression_test_cmd = b.addSystemCommand(&.{
        "bash",
        "scripts/run-vm-regression.sh",
        vm_readiness_regression_kernel.output_path,
        "vm_readiness_regression",
        "VMREADY",
        "build/vm-readiness-regression.log",
    });
    vm_readiness_regression_test_cmd.step.dependOn(vm_readiness_regression_kernel.install_step);

    const vm_readiness_regression_test_step = b.step("vm-readiness-regression-test", "Run the VM readiness regression profile in QEMU");
    vm_readiness_regression_test_step.dependOn(&vm_readiness_regression_test_cmd.step);

    const vm_memory_regression_test_cmd = b.addSystemCommand(&.{
        "bash",
        "scripts/run-vm-regression.sh",
        vm_memory_regression_kernel.output_path,
        "vm_memory_regression",
        "VMMEM",
        "build/vm-memory-regression.log",
    });
    vm_memory_regression_test_cmd.step.dependOn(vm_memory_regression_kernel.install_step);

    const vm_memory_regression_test_step = b.step("vm-memory-regression-test", "Run the VM memory regression profile in QEMU");
    vm_memory_regression_test_step.dependOn(&vm_memory_regression_test_cmd.step);

    const vm_state_regression_test_cmd = b.addSystemCommand(&.{
        "bash",
        "scripts/run-vm-regression.sh",
        vm_state_regression_kernel.output_path,
        "vm_state_regression",
        "VMSTATE",
        "build/vm-state-regression.log",
    });
    vm_state_regression_test_cmd.step.dependOn(vm_state_regression_kernel.install_step);

    const vm_state_regression_test_step = b.step("vm-state-regression-test", "Run the VM state regression profile in QEMU");
    vm_state_regression_test_step.dependOn(&vm_state_regression_test_cmd.step);

    const vm_tty_regression_test_cmd = b.addSystemCommand(&.{
        "bash",
        "scripts/run-vm-regression.sh",
        vm_tty_regression_kernel.output_path,
        "vm_tty_regression",
        "VMTTY",
        "build/vm-tty-regression.log",
    });
    vm_tty_regression_test_cmd.step.dependOn(vm_tty_regression_kernel.install_step);

    const vm_tty_regression_test_step = b.step("vm-tty-regression-test", "Run the VM tty regression profile in QEMU");
    vm_tty_regression_test_step.dependOn(&vm_tty_regression_test_cmd.step);

    const vm_socket_regression_test_cmd = b.addSystemCommand(&.{
        "bash",
        "scripts/run-vm-regression.sh",
        vm_socket_regression_kernel.output_path,
        "vm_socket_regression",
        "VMSOCK",
        "build/vm-socket-regression.log",
    });
    vm_socket_regression_test_cmd.step.dependOn(vm_socket_regression_kernel.install_step);

    const vm_socket_regression_test_step = b.step("vm-socket-regression-test", "Run the VM socket regression profile in QEMU");
    vm_socket_regression_test_step.dependOn(&vm_socket_regression_test_cmd.step);

    const vm_event_regression_test_cmd = b.addSystemCommand(&.{
        "bash",
        "scripts/run-vm-regression.sh",
        vm_event_regression_kernel.output_path,
        "vm_event_regression",
        "VMEVT",
        "build/vm-event-regression.log",
    });
    vm_event_regression_test_cmd.step.dependOn(vm_event_regression_kernel.install_step);

    const vm_event_regression_test_step = b.step("vm-event-regression-test", "Run the VM event regression profile in QEMU");
    vm_event_regression_test_step.dependOn(&vm_event_regression_test_cmd.step);

    const vm_inotify_regression_test_cmd = b.addSystemCommand(&.{
        "bash",
        "scripts/run-vm-regression.sh",
        vm_inotify_regression_kernel.output_path,
        "vm_inotify_regression",
        "VMINOTIFY",
        "build/vm-inotify-regression.log",
    });
    vm_inotify_regression_test_cmd.step.dependOn(vm_inotify_regression_kernel.install_step);

    const vm_inotify_regression_test_step = b.step("vm-inotify-regression-test", "Run the VM inotify regression profile in QEMU");
    vm_inotify_regression_test_step.dependOn(&vm_inotify_regression_test_cmd.step);

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

    const smp_regression_test_cmd = b.addSystemCommand(&.{
        "bash",
        "scripts/run-smp-regression.sh",
        smp_regression_kernel.output_path,
        "build/smp-regression.log",
    });
    smp_regression_test_cmd.step.dependOn(smp_regression_kernel.install_step);

    const smp_regression_test_step = b.step("smp-regression-test", "Run the automated SMP regression profile in QEMU");
    smp_regression_test_step.dependOn(&smp_regression_test_cmd.step);

    const manual_regression_test_cmd = b.addSystemCommand(&.{
        "bash",
        "scripts/run-manual-regression.sh",
        manual_regression_kernel.output_path,
        shared.rootfs_image_path,
        "build/manual-regression.log",
    });
    manual_regression_test_cmd.step.dependOn(manual_regression_kernel.install_step);
    manual_regression_test_cmd.step.dependOn(&rootfs_cmd.step);

    const manual_regression_test_step = b.step("manual-regression-test", "Run the automated manual regression kernel profile in QEMU");
    manual_regression_test_step.dependOn(&manual_regression_test_cmd.step);

    const ext2_regression_test_cmd = b.addSystemCommand(&.{
        "bash",
        "scripts/run-ext2-regression.sh",
        ext2_regression_kernel.output_path,
        shared.rootfs_image_path,
        "build/ext2.img",
        "build/ext2-regression.log",
    });
    ext2_regression_test_cmd.step.dependOn(ext2_regression_kernel.install_step);
    ext2_regression_test_cmd.step.dependOn(&rootfs_cmd.step);
    ext2_regression_test_cmd.step.dependOn(&ext2_image_cmd.step);

    const ext2_regression_test_step = b.step("ext2-regression-test", "Run the automated ext2 regression profile in QEMU");
    ext2_regression_test_step.dependOn(&ext2_regression_test_cmd.step);

    const service_regression_test_cmd = b.addSystemCommand(&.{
        "bash",
        "scripts/run-service-regression.sh",
        service_regression_kernel.output_path,
        "build/service-regression.log",
    });
    service_regression_test_cmd.step.dependOn(service_regression_kernel.install_step);

    const service_regression_test_step = b.step("service-regression-test", "Run the automated service regression kernel profile in QEMU");
    service_regression_test_step.dependOn(&service_regression_test_cmd.step);

    const scheduler_regression_test_cmd = b.addSystemCommand(&.{
        "bash",
        "scripts/run-scheduler-regression.sh",
        scheduler_regression_kernel.output_path,
        "build/scheduler-regression.log",
    });
    scheduler_regression_test_cmd.step.dependOn(scheduler_regression_kernel.install_step);

    const scheduler_regression_test_step = b.step("scheduler-regression-test", "Run the automated scheduler regression kernel profile in QEMU");
    scheduler_regression_test_step.dependOn(&scheduler_regression_test_cmd.step);

    const nic_ingress_test_cmd = b.addSystemCommand(&.{
        "bash",
        "scripts/run-nic-ingress-regression.sh",
        nic_ingress_kernel.output_path,
        "build/nic-ingress.log",
    });
    nic_ingress_test_cmd.step.dependOn(nic_ingress_kernel.install_step);

    const nic_ingress_test_step = b.step("nic-ingress-test", "Run the NIC ingress regression profile in QEMU");
    nic_ingress_test_step.dependOn(&nic_ingress_test_cmd.step);

    const e1000_ingress_test_cmd = b.addSystemCommand(&.{
        "bash",
        "scripts/run-e1000-live-ingress.sh",
        e1000_ingress_kernel.output_path,
        "build/e1000-live-ingress.log",
    });
    e1000_ingress_test_cmd.step.dependOn(e1000_ingress_kernel.install_step);

    const e1000_ingress_test_step = b.step("e1000-ingress-test", "Run the E1000 live ingress regression profile in QEMU");
    e1000_ingress_test_step.dependOn(&e1000_ingress_test_cmd.step);

    const virtio_ingress_test_cmd = b.addSystemCommand(&.{
        "bash",
        "scripts/run-virtio-live-ingress.sh",
        virtio_ingress_kernel.output_path,
        "build/virtio-live-ingress.log",
    });
    virtio_ingress_test_cmd.step.dependOn(virtio_ingress_kernel.install_step);

    const virtio_ingress_test_step = b.step("virtio-ingress-test", "Run the VirtIO live ingress regression profile in QEMU");
    virtio_ingress_test_step.dependOn(&virtio_ingress_test_cmd.step);

    const host_tests_cmd = b.addSystemCommand(&.{
        "bash",
        "scripts/run-host-tests.sh",
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

    const benchmark_ci_run = b.addRunArtifact(benchmark_exe);
    benchmark_ci_run.addArgs(&.{
        "--duration-ms",
        "50",
        "--warmup-ms",
        "10",
        "--min-batch",
        "32",
    });

    const benchmark_ci_step = b.step("bench-ci", "Run host-side benchmark smoke coverage");
    benchmark_ci_step.dependOn(&benchmark_ci_run.step);

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
