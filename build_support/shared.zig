const std = @import("std");

pub const BootProfile = enum {
    zigos_native,
    recovery,
    benchmark,
};

pub const KernelArtifact = struct {
    compile_step: *std.Build.Step.Compile,
    install_step: *std.Build.Step,
    output_path: []const u8,
};

pub const native_store_image_path = "build/native-store.img";
pub const native_store_smoke_image_path = "build/native-store-smoke.img";
