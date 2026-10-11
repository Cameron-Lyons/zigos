// Native EFI handoff memory classes. Device memory and runtime firmware RAM
// must remain distinguishable after ExitBootServices for cache ownership.
pub const Kind = enum(u32) {
    available = 1,
    reserved = 2,
    acpi_reclaimable = 3,
    acpi_nvs = 4,
    bad_ram = 5,
    device_mmio = 6,
    firmware_runtime_ram = 7,
    _,
};

// Preserve the EFI classification separately from allocator reservations:
// reserving loader RAM does not turn it into an unknown/device aperture.
pub fn efiTypeIsRam(firmware_type: u32) bool {
    return switch (firmware_type) {
        1, 2, 3, 4, 5, 6, 7, 9, 10, 14 => true,
        else => false,
    };
}
