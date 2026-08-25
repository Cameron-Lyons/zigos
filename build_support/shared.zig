const std = @import("std");

pub const BootProfile = enum {
    zigos_native,
    recovery,
    benchmark,
};

pub const KernelRole = enum {
    production,
    verification,
};

pub const SmokeFaultMode = enum {
    none,
    tampered_artifact_manifest,
    tampered_bootloader_measurement,
    tampered_kernel,
    tampered_userspace_image,
    tampered_policy,
    tampered_driver_set,
    rollback_slot_failure,
    storage_durability,
};

pub const KernelArtifact = struct {
    compile_step: *std.Build.Step.Compile,
    output_file: std.Build.LazyPath,
    install_step: *std.Build.Step,
    output_path: []const u8,
    kernel_role: KernelRole,
    bootloader_source_path: []const u8,
    qemu_boot_iso_path: std.Build.LazyPath,
};

pub const native_store_image_path = "build/native-store.img";
pub const native_store_smoke_image_path = "build/native-store-smoke.img";
pub const native_store_spec_image_path = "build/native-store-spec.img";
pub const native_store_size_mib = "8";
