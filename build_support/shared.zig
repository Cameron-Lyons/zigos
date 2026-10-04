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
    boot_payload: std.Build.LazyPath,
    install_step: *std.Build.Step,
    debug_install_step: *std.Build.Step,
    output_path: std.Build.LazyPath,
    kernel_role: KernelRole,
    bootloader_source_path: []const u8,
    qemu_boot_iso_path: std.Build.LazyPath,
};

pub const native_store_image_path = "build/native-store.img";
pub const native_store_smoke_image_path = "build/native-store-smoke.img";
pub const native_store_spec_image_path = "build/native-store-spec.img";
pub const native_store_size_mib = "8";

pub fn addEfiIsoEpochArg(b: *std.Build, command: *std.Build.Step.Run) void {
    const name = "source-date-epoch";
    const default_epoch = "315532800";
    // Declare the option once even when several EFI images share this Build.
    // Pass SOURCE_DATE_EPOCH as -Dsource-date-epoch explicitly. The configuration
    // input invalidates both the configure cache and the media Run step.
    const epoch = if (!b.available_options_map.contains(name))
        b.option([]const u8, name, "EFI media timestamp in decimal Unix seconds (defaults to 1980-01-01 UTC)") orelse default_epoch
    else if (b.user_input_options.get(name)) |value|
        switch (value) {
            .scalar => |scalar| scalar,
            else => default_epoch,
        }
    else
        default_epoch;
    command.addArg(epoch);
}
