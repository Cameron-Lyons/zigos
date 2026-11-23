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

/// The `build_options` module every kernel, probe and kernel-logic test imports.
pub fn kernelOptions(b: *std.Build, boot_profile: BootProfile, kernel_role: KernelRole) *std.Build.Step.Options {
    const options = b.addOptions();
    options.addOption(BootProfile, "boot_profile", boot_profile);
    options.addOption(KernelRole, "kernel_role", kernel_role);
    return options;
}

pub const KernelArtifact = struct {
    /// The stripped ELF that firmware measures, published to zig-out/bin.
    output_file: std.Build.LazyPath,
    install_step: *std.Build.Step,
    output_path: std.Build.LazyPath,
    kernel_role: KernelRole,
    qemu_boot_iso_path: std.Build.LazyPath,
};

pub const bootloader_source_path = "src/boot/efi_stub.zig";
pub const qemu_cmdline_path = "src/boot/cmdline-qemu.txt";
pub const native_store_image_path = "build/native-store.img";
pub const native_store_smoke_image_path = "build/native-store-smoke.img";
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
