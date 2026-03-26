const std = @import("std");

pub const BootProfile = enum {
    dev,
    ci_smoke,
    test_vm,
    vm_core_regression,
    vm_readiness_regression,
    vm_memory_regression,
    vm_state_regression,
    vm_tty_regression,
    vm_socket_regression,
    vm_event_regression,
    vm_inotify_regression,
    benchmark,
    smp_stress,
    smp_regression,
    manual_regression,
    ext2_regression,
    userland_smoke,
    userland_sh_smoke,
};

pub const KernelArtifact = struct {
    compile_step: *std.Build.Step.Compile,
    install_step: *std.Build.Step,
    output_path: []const u8,
};

pub const UserProgramArtifact = struct {
    install_step: *std.Build.Step,
    emitted_bin: std.Build.LazyPath,
    output_path: []const u8,
};

pub const UserProgramSpec = struct {
    name: []const u8,
    root_source: []const u8,
};

pub const rootfs_image_path = "build/disk.img";
