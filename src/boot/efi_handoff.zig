// EFI-side translation into the typed BootInfo (boot_info.zig).
const std = @import("std");
pub const boot_info = @import("boot_info.zig");
pub const image_info = boot_info.image_info;
pub const tpm_info = boot_info.tpm_info;
pub const memory_kind = boot_info.memory_kind;
pub const paging_info = boot_info.paging_info;
const MemoryKind = boot_info.MemoryKind;

pub const EFI_MEMORY_TYPE_RESERVED: u32 = 0;
pub const EFI_MEMORY_TYPE_LOADER_CODE: u32 = 1;
pub const EFI_MEMORY_TYPE_LOADER_DATA: u32 = 2;
pub const EFI_MEMORY_TYPE_BOOT_SERVICES_CODE: u32 = 3;
pub const EFI_MEMORY_TYPE_BOOT_SERVICES_DATA: u32 = 4;
pub const EFI_MEMORY_TYPE_RUNTIME_SERVICES_CODE: u32 = 5;
pub const EFI_MEMORY_TYPE_RUNTIME_SERVICES_DATA: u32 = 6;
pub const EFI_MEMORY_TYPE_CONVENTIONAL: u32 = 7;
pub const EFI_MEMORY_TYPE_UNUSABLE: u32 = 8;
pub const EFI_MEMORY_TYPE_ACPI_RECLAIM: u32 = 9;
pub const EFI_MEMORY_TYPE_ACPI_NVS: u32 = 10;
pub const EFI_MEMORY_TYPE_MMIO: u32 = 11;
pub const EFI_MEMORY_TYPE_MMIO_PORT_SPACE: u32 = 12;
pub const EFI_MEMORY_TYPE_PAL_CODE: u32 = 13;
pub const EFI_MEMORY_TYPE_PERSISTENT: u32 = 14;

pub fn kindFromEfiMemoryType(efi_type: u32) MemoryKind {
    return switch (efi_type) {
        EFI_MEMORY_TYPE_LOADER_CODE,
        EFI_MEMORY_TYPE_LOADER_DATA,
        EFI_MEMORY_TYPE_BOOT_SERVICES_CODE,
        EFI_MEMORY_TYPE_BOOT_SERVICES_DATA,
        EFI_MEMORY_TYPE_CONVENTIONAL,
        EFI_MEMORY_TYPE_PERSISTENT,
        => .available,
        EFI_MEMORY_TYPE_ACPI_RECLAIM => .acpi_reclaimable,
        EFI_MEMORY_TYPE_ACPI_NVS => .acpi_nvs,
        EFI_MEMORY_TYPE_UNUSABLE => .bad_ram,
        EFI_MEMORY_TYPE_MMIO => .device_mmio,
        EFI_MEMORY_TYPE_RUNTIME_SERVICES_CODE,
        EFI_MEMORY_TYPE_RUNTIME_SERVICES_DATA,
        => .firmware_runtime_ram,
        else => .reserved,
    };
}

pub fn embeddedCommandLine(bytes: []const u8) error{InvalidCommandLine}![]const u8 {
    if (bytes.len > boot_info.MAX_COMMAND_LINE_BYTES) return error.InvalidCommandLine;
    const result = std.mem.trim(u8, bytes, " \t\r\n");
    for (result) |byte| if (byte != '\t' and (byte < 0x20 or byte > 0x7e)) return error.InvalidCommandLine;
    return result;
}

test "EFI embedded command line rejects truncation and control bytes" {
    try std.testing.expectEqualStrings("model_inventory", try embeddedCommandLine("model_inventory\n"));
    try std.testing.expectEqualStrings("", try embeddedCommandLine("\r\n"));
    for ([_][]const u8{ "x\x00y", "x\ny", "x\x7f", &@as([257]u8, @splat('x')) }) |invalid|
        try std.testing.expectError(error.InvalidCommandLine, embeddedCommandLine(invalid));
}

test "native EFI memory kinds preserve device and runtime RAM ownership" {
    try std.testing.expectEqual(MemoryKind.available, kindFromEfiMemoryType(EFI_MEMORY_TYPE_CONVENTIONAL));
    try std.testing.expectEqual(MemoryKind.available, kindFromEfiMemoryType(EFI_MEMORY_TYPE_LOADER_DATA));
    try std.testing.expectEqual(MemoryKind.acpi_reclaimable, kindFromEfiMemoryType(EFI_MEMORY_TYPE_ACPI_RECLAIM));
    try std.testing.expectEqual(MemoryKind.acpi_nvs, kindFromEfiMemoryType(EFI_MEMORY_TYPE_ACPI_NVS));
    try std.testing.expectEqual(MemoryKind.firmware_runtime_ram, kindFromEfiMemoryType(EFI_MEMORY_TYPE_RUNTIME_SERVICES_CODE));
    try std.testing.expectEqual(MemoryKind.firmware_runtime_ram, kindFromEfiMemoryType(EFI_MEMORY_TYPE_RUNTIME_SERVICES_DATA));
    try std.testing.expectEqual(MemoryKind.device_mmio, kindFromEfiMemoryType(EFI_MEMORY_TYPE_MMIO));
    for ([_]u32{ EFI_MEMORY_TYPE_RESERVED, EFI_MEMORY_TYPE_MMIO_PORT_SPACE, EFI_MEMORY_TYPE_PAL_CODE, 0xffff }) |efi_type|
        try std.testing.expectEqual(MemoryKind.reserved, kindFromEfiMemoryType(efi_type));
}
