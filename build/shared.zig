const std = @import("std");

pub const BootProfile = enum {
    dev,
    ci_smoke,
    test_vm,
    benchmark,
    smp_stress,
    userland_smoke,
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
