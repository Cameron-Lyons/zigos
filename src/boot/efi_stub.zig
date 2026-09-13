const std = @import("std");
const uefi = std.os.uefi;
const efi_elf = @import("efi_elf.zig");
const efi_handoff = @import("efi_handoff.zig");

pub const NATIVE_EFI_LONG_MODE_ENTRY = true;
pub const DROPS_MULTIBOOT2_PROTECTED_MODE_ENTRY = true;

const KERNEL_PATH = [_:0]u16{ '\\', 'b', 'o', 'o', 't', '\\', 'k', 'e', 'r', 'n', 'e', 'l', '.', 'e', 'l', 'f' };
const CMDLINE_PATH = [_:0]u16{ '\\', 'b', 'o', 'o', 't', '\\', 'c', 'm', 'd', 'l', 'i', 'n', 'e', '.', 't', 'x', 't' };
const KERNEL_MAX_BYTES: usize = 16 * 1024 * 1024;
const HANDOFF_PAGES: usize = 8;
const MMAP_ENTRY_CAP: usize = 256;
const CMDLINE_CAP: usize = 256;
const RSDP_CAP: usize = 64;
const MAX_BELOW_4G: usize = 0xFFFFF000;

pub fn main() uefi.Status {
    const system_table = uefi.system_table;
    const boot = system_table.boot_services orelse return .unsupported;
    boot.setWatchdogTimer(0, 0, null) catch {};

    const loaded = boot.openProtocol(uefi.protocol.LoadedImage, uefi.handle, .{
        .get_protocol = .{ .agent = uefi.handle },
    }) catch return .load_error;
    const loaded_image = loaded orelse return .load_error;
    const device = loaded_image.device_handle orelse return .no_media;

    const volume_protocol = boot.openProtocol(uefi.protocol.SimpleFileSystem, device, .{
        .get_protocol = .{ .agent = uefi.handle },
    }) catch return .no_media;
    const volume = (volume_protocol orelse return .no_media).openVolume() catch return .no_media;

    const kernel_bytes = readFile(volume, &KERNEL_PATH, KERNEL_MAX_BYTES) catch return .load_error;
    const image = efi_elf.parse(kernel_bytes) catch return .incompatible_version;

    var cmdline_buf: [CMDLINE_CAP]u8 = undefined;
    const cmdline = loadCommandLine(loaded_image, volume, &cmdline_buf);

    const framebuffer = readFramebuffer(boot);
    var rsdp_buf: [RSDP_CAP]u8 = undefined;
    const rsdp = readAcpiRsdp(system_table, &rsdp_buf);

    efi_elf.load(kernel_bytes, image);

    const handoff_pages = boot.allocatePages(
        .{ .max_address = @ptrFromInt(MAX_BELOW_4G) },
        .loader_data,
        HANDOFF_PAGES,
    ) catch return .out_of_resources;
    const handoff_bytes: []u8 = @as([*]u8, @ptrCast(handoff_pages.ptr))[0 .. HANDOFF_PAGES * 4096];
    const info_addr: u32 = @intCast(@intFromPtr(handoff_bytes.ptr));

    var mmap_entries: [MMAP_ENTRY_CAP]efi_handoff.MmapEntry = undefined;
    const map_slice, const mmap_count = captureMemoryMap(boot, &mmap_entries) catch
        return .out_of_resources;
    boot.exitBootServices(uefi.handle, map_slice.info.key) catch return .aborted;

    const encoded = efi_handoff.encode(handoff_bytes, .{
        .cmdline = cmdline,
        .mmap = mmap_entries[0..mmap_count],
        .framebuffer = framebuffer,
        .efi_system_table = @intFromPtr(system_table),
        .acpi_rsdp = rsdp,
    }) catch return .load_error;
    _ = encoded;

    enterKernel(image.entry, info_addr);
}

fn readFile(root: *uefi.protocol.File, path: [*:0]const u16, max_bytes: usize) ![]u8 {
    const boot = uefi.system_table.boot_services orelse return error.OutOfResources;
    const file = try root.open(path, .read, .{});
    defer file.close() catch {};
    const buffer = try boot.allocatePool(.loader_data, max_bytes);
    const read_n = try file.read(buffer);
    if (read_n == 0 or read_n == max_bytes) return error.InvalidParameter;
    return buffer[0..read_n];
}

fn loadCommandLine(
    loaded: *uefi.protocol.LoadedImage,
    root: *uefi.protocol.File,
    buffer: []u8,
) []const u8 {
    if (utf16LoadOptions(loaded, buffer)) |cmdline| return cmdline;
    const file_bytes = readFile(root, &CMDLINE_PATH, buffer.len) catch return &.{};
    var len = file_bytes.len;
    while (len > 0 and (file_bytes[len - 1] == 0 or file_bytes[len - 1] == '\n' or file_bytes[len - 1] == '\r')) {
        len -= 1;
    }
    const copied = @min(len, buffer.len);
    @memcpy(buffer[0..copied], file_bytes[0..copied]);
    return buffer[0..copied];
}

fn utf16LoadOptions(loaded: *uefi.protocol.LoadedImage, buffer: []u8) ?[]const u8 {
    if (loaded.load_options_size < 2 or loaded.load_options == null) return null;
    const words = loaded.load_options_size / 2;
    const utf16: [*]const u16 = @ptrCast(@alignCast(loaded.load_options.?));
    var len: usize = 0;
    while (len < words and len < buffer.len) : (len += 1) {
        const unit = utf16[len];
        if (unit == 0) break;
        if (unit > 0x7F) return null;
        buffer[len] = @intCast(unit);
    }
    return buffer[0..len];
}

fn readFramebuffer(boot: *uefi.tables.BootServices) ?efi_handoff.Framebuffer {
    const gop = boot.locateProtocol(uefi.protocol.GraphicsOutput, null) catch return null;
    const protocol = gop orelse return null;
    const mode = protocol.mode;
    const info = mode.info;
    if (info.horizontal_resolution == 0 or info.vertical_resolution == 0) return null;
    const rgb = switch (info.pixel_format) {
        .red_green_blue_reserved_8_bit_per_color => efi_handoff.rgbFromMasks(0, 8, 16),
        .blue_green_red_reserved_8_bit_per_color => efi_handoff.rgbFromMasks(16, 8, 0),
        else => return null,
    };
    return .{
        .addr = mode.frame_buffer_base,
        .pitch = info.pixels_per_scan_line * 4,
        .width = info.horizontal_resolution,
        .height = info.vertical_resolution,
        .rgb = rgb,
    };
}

fn readAcpiRsdp(system_table: *uefi.tables.SystemTable, buffer: []u8) []const u8 {
    var index: usize = 0;
    while (index < system_table.number_of_table_entries) : (index += 1) {
        const entry = system_table.configuration_table[index];
        if (!uefi.Guid.eql(entry.vendor_guid, uefi.tables.ConfigurationTable.acpi_20_table_guid)) {
            continue;
        }
        const rsdp: [*]const u8 = @ptrCast(entry.vendor_table);
        const length = if (std.mem.eql(u8, rsdp[0..8], "RSD PTR "))
            @max(
                efi_handoff.ACPI_RSDP_V2_MIN_BYTES,
                @as(u32, rsdp[20]) |
                    (@as(u32, rsdp[21]) << 8) |
                    (@as(u32, rsdp[22]) << 16) |
                    (@as(u32, rsdp[23]) << 24),
            )
        else
            efi_handoff.ACPI_RSDP_V2_MIN_BYTES;
        const copied = @min(length, buffer.len);
        @memcpy(buffer[0..copied], rsdp[0..copied]);
        return buffer[0..copied];
    }
    return &.{};
}

fn captureMemoryMap(
    boot: *uefi.tables.BootServices,
    entries: []efi_handoff.MmapEntry,
) !struct { uefi.tables.MemoryMapSlice, usize } {
    const info = try boot.getMemoryMapInfo();
    const byte_count = (info.len + 16) * info.descriptor_size;
    const aligned_count = std.mem.alignForward(usize, byte_count, @alignOf(uefi.tables.MemoryDescriptor));
    const raw = try boot.allocatePool(.loader_data, aligned_count);
    const buffer: []align(@alignOf(uefi.tables.MemoryDescriptor)) u8 = @alignCast(raw[0..aligned_count]);
    const slice = try boot.getMemoryMap(buffer);
    var count: usize = 0;
    var iterator = slice.iterator();
    while (iterator.next()) |descriptor| {
        if (count == entries.len) break;
        const pages = descriptor.number_of_pages;
        const length = std.math.mul(u64, pages, 4096) catch continue;
        if (length == 0) continue;
        entries[count] = .{
            .base = descriptor.physical_start,
            .length = length,
            .kind = efi_handoff.kindFromEfiMemoryType(@intFromEnum(descriptor.type)),
        };
        count += 1;
    }
    if (count == 0) return error.InvalidParameter;
    return .{ slice, count };
}

fn enterKernel(entry: u64, info_addr: u32) noreturn {
    asm volatile (
        \\cli
        \\movq %[info], %%rdi
        \\jmpq *%[entry]
        :
        : [info] "r" (@as(u64, info_addr)),
          [entry] "r" (entry),
        : .{ .rdi = true, .memory = true }
    );
    unreachable;
}
