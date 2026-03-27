const std = @import("std");
const shared = @import("build/shared.zig");
const kernel_build = @import("build/kernel.zig");

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

    const zigos_native_kernel = kernel_build.addKernelArtifact(
        b,
        target,
        optimize,
        "kernel-zigos-native.elf",
        .zigos_native,
    );

    const kernel_step = b.step("kernel", "Build the native-only Zigos kernel");
    kernel_step.dependOn(zigos_native_kernel.install_step);

    const zigos_native_kernel_step = b.step("kernel-zigos-native", "Build the Zigos native bootstrap kernel");
    zigos_native_kernel_step.dependOn(zigos_native_kernel.install_step);

    const native_store_cmd = b.addSystemCommand(&.{
        "bash",
        "scripts/build-native-store.sh",
        shared.native_store_image_path,
        "8",
        "preserve",
    });

    const native_store_step = b.step("native-store-image", "Build or preserve the dedicated native storage image");
    native_store_step.dependOn(&native_store_cmd.step);

    const zigos_native_qemu_cmd = b.addSystemCommand(&.{
        "qemu-system-x86_64",
        "-kernel",
        zigos_native_kernel.output_path,
        "-m",
        "256M",
        "-display",
        "none",
        "-serial",
        "stdio",
        "-monitor",
        "none",
        "-no-reboot",
        "-no-shutdown",
        "-drive",
        "file=" ++ shared.native_store_image_path ++ ",if=ide,format=raw,index=1,id=disk1",
    });
    zigos_native_qemu_cmd.step.dependOn(zigos_native_kernel.install_step);
    zigos_native_qemu_cmd.step.dependOn(&native_store_cmd.step);

    const run_step = b.step("run", "Run the native-only Zigos kernel in QEMU");
    run_step.dependOn(&zigos_native_qemu_cmd.step);

    const run_zigos_native_step = b.step("run-zigos-native", "Run the Zigos native bootstrap kernel in QEMU");
    run_zigos_native_step.dependOn(&zigos_native_qemu_cmd.step);

    const zigos_native_smoke_test_cmd = b.addSystemCommand(&.{
        "bash",
        "scripts/run-zigos-native-smoke.sh",
        zigos_native_kernel.output_path,
        "build/zigos-native-smoke.log",
        shared.native_store_smoke_image_path,
    });
    zigos_native_smoke_test_cmd.step.dependOn(zigos_native_kernel.install_step);

    const zigos_native_smoke_test_step = b.step("zigos-native-smoke-test", "Run the Zigos native bootstrap smoke test in QEMU");
    zigos_native_smoke_test_step.dependOn(&zigos_native_smoke_test_cmd.step);

    const host_tests_cmd = b.addSystemCommand(&.{
        "bash",
        "scripts/run-host-tests.sh",
    });
    const host_tests_step = b.step("host-tests", "Run host-side unit tests for native logic");
    host_tests_step.dependOn(&host_tests_cmd.step);

    const iso_cmd = b.addSystemCommand(&.{
        "bash",
        "scripts/build-grub-iso.sh",
        zigos_native_kernel.output_path,
        "build/os.iso",
        "build/iso",
    });
    iso_cmd.step.dependOn(zigos_native_kernel.install_step);

    const iso_step = b.step("iso", "Build a bootable native-only ISO");
    iso_step.dependOn(&iso_cmd.step);
}
