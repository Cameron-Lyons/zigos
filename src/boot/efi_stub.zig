const std = @import("std");
const uefi = std.os.uefi;
const efi_elf = @import("efi_elf.zig");
const efi_handoff = @import("efi_handoff.zig");
const payload = @import("boot_payload");
const tcg2 = @import("efi_tcg2.zig");

pub const NATIVE_EFI_LONG_MODE_ENTRY = true;
pub const DROPS_MULTIBOOT2_PROTECTED_MODE_ENTRY = true;

const HANDOFF_PAGES: usize = 8;
const MMAP_ENTRY_CAP: usize = 256;
const RSDP_CAP: usize = 64;
const HANDOFF_MAX_ADDRESS: usize = 128 * 1024 * 1024;

pub fn main() uefi.Status {
    const system_table = uefi.system_table;
    const boot = system_table.boot_services orelse return .unsupported;
    boot.setWatchdogTimer(0, 0, null) catch {};

    const kernel_bytes = payload.kernel;
    const image = efi_elf.parse(kernel_bytes) catch return .incompatible_version;
    const cmdline = efi_handoff.embeddedCommandLine(payload.cmdline) catch return .invalid_parameter;
    const authenticated = firmwareAuthenticated(system_table);

    const framebuffer = readFramebuffer(boot);
    var rsdp_buf: [RSDP_CAP]u8 = undefined;
    const rsdp = readAcpiRsdp(system_table, &rsdp_buf);

    // Claim the destination before copying. Firmware, the EFI image itself,
    // and every other live allocation must be outside these disjoint pages.
    var reserved: usize = 0;
    defer for (image.segments[0..reserved]) |prior| {
        const pages: [*]align(4096) uefi.Page = @ptrFromInt(@as(usize, @intCast(prior.phys_addr)));
        boot.freePages(pages[0..prior.pageCount()]) catch {};
    };
    for (image.segments[0..image.segment_count]) |segment| {
        _ = boot.allocatePages(.{ .address = @ptrFromInt(@as(usize, @intCast(segment.phys_addr))) }, .loader_code, segment.pageCount()) catch {
            reportReservationConflict(boot, segment);
            return bootFailure("kernel-reservation", .out_of_resources);
        };
        reserved += 1;
    }
    efi_elf.load(kernel_bytes, image);

    // The early allocator must also own real firmware-allocated pages. Memory
    // immediately after the ELF can contain ACPI NVS, runtime data, or the EFI
    // image itself, even when the kernel's load segments fit in free memory.
    const heap_pages = boot.allocatePages(
        .{ .max_address = @ptrFromInt(efi_handoff.image_info.IDENTITY_LIMIT) },
        .loader_data,
        efi_handoff.image_info.KERNEL_HEAP_BYTES / 4096,
    ) catch return bootFailure("heap-reservation", .out_of_resources);
    defer boot.freePages(heap_pages) catch {};
    const boot_image = efi_handoff.image_info.Info.measure(kernel_bytes, cmdline, authenticated, @intFromPtr(heap_pages.ptr));
    var measurement = tcg2.capture(boot, system_table, boot_image) catch return bootFailure("tpm-measurement", .security_violation);
    defer if (measurement) |captured| boot.freePages(captured.pages) catch {};

    const handoff_pages = boot.allocatePages(
        .{ .max_address = @ptrFromInt(HANDOFF_MAX_ADDRESS) },
        .loader_data,
        HANDOFF_PAGES,
    ) catch return bootFailure("handoff-reservation", .out_of_resources);
    defer boot.freePages(handoff_pages) catch {};
    const handoff_bytes: []u8 = @as([*]u8, @ptrCast(handoff_pages.ptr))[0 .. HANDOFF_PAGES * 4096];
    const info_addr: u32 = @intCast(@intFromPtr(handoff_bytes.ptr));

    var mmap_entries: [MMAP_ENTRY_CAP]efi_handoff.MmapEntry = undefined;
    const map_info = boot.getMemoryMapInfo() catch return bootFailure("map-size", .out_of_resources);
    const descriptor_count = std.math.add(usize, map_info.len, 16) catch return .out_of_resources;
    const byte_count = std.math.mul(usize, descriptor_count, map_info.descriptor_size) catch return .out_of_resources;
    const raw_map = boot.allocatePool(.loader_data, byte_count) catch return bootFailure("map-reservation", .out_of_resources);
    defer boot.freePool(raw_map.ptr) catch {};
    const map_buffer: []align(@alignOf(uefi.tables.MemoryDescriptor)) u8 = @alignCast(raw_map);

    // Build the complete handoff before leaving firmware. If a firmware exit
    // notification changes the map, refresh it in the same allocation and retry.
    for (0..2) |attempt| {
        const map_slice = boot.getMemoryMap(map_buffer) catch {
            if (attempt != 0) return .out_of_resources;
            return bootFailure("map-read", .out_of_resources);
        };
        const mmap_count = captureMemoryMap(map_slice, &mmap_entries) catch |err| {
            if (attempt != 0) return .out_of_resources;
            return switch (err) {
                error.BufferTooSmall => bootFailure("map-capacity", .out_of_resources),
                else => bootFailure("map-invalid", .out_of_resources),
            };
        };
        var request = efi_handoff.Request{
            .cmdline = cmdline,
            .mmap = mmap_entries[0..mmap_count],
            .framebuffer = framebuffer,
            .efi_system_table = @intFromPtr(system_table),
            .acpi_rsdp = rsdp,
            .boot_image = boot_image,
            .boot_tpm = if (measurement) |captured| captured.info else null,
        };
        _ = efi_handoff.encode(handoff_bytes, request) catch return .load_error;
        boot.exitBootServices(uefi.handle, map_slice.info.key) catch continue;
        // No firmware calls or allocations after this point. Keep the firmware
        // mappings until its final events have been copied into owned low pages.
        asm volatile ("cli" ::: .{ .memory = true });
        if (measurement) |*captured| {
            captured.finish(boot_image) catch haltAfterExit();
            request.boot_tpm = captured.info;
            // This exact-sized encoding already succeeded before firmware exit.
            _ = efi_handoff.encode(handoff_bytes, request) catch haltAfterExit();
        }
        enterKernel(image.entry, info_addr);
    }
    return .aborted;
}

fn haltAfterExit() noreturn {
    // The firmware console is gone. Report through the x86 debug serial port
    // with a bounded wait, then stop without running boot-service defers.
    for ("EFI:FAIL:tpm-final-events\r\n") |byte| {
        for (0..10_000) |_| {
            const status = asm volatile ("inb %[port], %[result]"
                : [result] "={al}" (-> u8),
                : [port] "{dx}" (@as(u16, 0x3fd)),
            );
            if (status & 0x20 != 0) break;
            asm volatile ("pause");
        }
        asm volatile ("outb %[value], %[port]"
            :
            : [value] "{al}" (byte),
              [port] "{dx}" (@as(u16, 0x3f8)),
        );
    }
    while (true) asm volatile ("hlt");
}

fn bootFailure(comptime stage: []const u8, status: uefi.Status) uefi.Status {
    if (uefi.system_table.con_out) |out| {
        _ = out.outputString(std.unicode.utf8ToUtf16LeStringLiteral("EFI:FAIL:" ++ stage ++ "\r\n")) catch false;
    }
    return status;
}

fn reportReservationConflict(boot: *uefi.tables.BootServices, segment: efi_elf.Segment) void {
    const info = boot.getMemoryMapInfo() catch return;
    const count = std.math.add(usize, info.len, 16) catch return;
    const bytes = std.math.mul(usize, count, info.descriptor_size) catch return;
    const raw = boot.allocatePool(.loader_data, bytes) catch return;
    defer boot.freePool(raw.ptr) catch {};
    const map = boot.getMemoryMap(@alignCast(raw)) catch return;
    var iter = map.iterator();
    while (iter.next()) |entry| {
        const length = std.math.mul(u64, entry.number_of_pages, 4096) catch return;
        const end = std.math.add(u64, entry.physical_start, length) catch return;
        if (entry.physical_start >= segment.phys_addr + segment.mem_size or end <= segment.phys_addr) continue;
        var ascii: [160]u8 = undefined;
        const line = std.fmt.bufPrint(&ascii, "EFI:RESERVATION:{s} {x}-{x}\r\n", .{ @tagName(entry.type), entry.physical_start, end }) catch return;
        var wide: [160:0]u16 = @splat(0);
        for (line, 0..) |byte, i| wide[i] = byte;
        if (uefi.system_table.con_out) |out| _ = out.outputString(&wide) catch false;
    }
}

fn firmwareAuthenticated(system_table: *uefi.tables.SystemTable) bool {
    return efi_handoff.image_info.authenticatedFirmwareState(
        readFirmwareByte(system_table, "SecureBoot") catch return false,
        readFirmwareByte(system_table, "SetupMode") catch return false,
        readFirmwareByte(system_table, "AuditMode") catch return false,
    );
}

fn readFirmwareByte(system_table: *uefi.tables.SystemTable, comptime name: []const u8) !?u8 {
    var bytes: [1]u8 = undefined;
    const value = try system_table.runtime_services.getVariable(
        std.unicode.utf8ToUtf16LeStringLiteral(name),
        &uefi.tables.global_variable,
        &bytes,
    );
    const data, _ = value orelse return null;
    if (data.len != 1) return error.InvalidFirmwareState;
    return data[0];
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
    slice: uefi.tables.MemoryMapSlice,
    entries: []efi_handoff.MmapEntry,
) !usize {
    var count: usize = 0;
    var iterator = slice.iterator();
    while (iterator.next()) |descriptor| {
        const pages = descriptor.number_of_pages;
        const length = try std.math.mul(u64, pages, 4096);
        if (length == 0) continue;
        if (count == entries.len) return error.BufferTooSmall;
        _ = try std.math.add(u64, descriptor.physical_start, length);
        entries[count] = .{
            .base = descriptor.physical_start,
            .length = length,
            .kind = efi_handoff.kindFromEfiMemoryType(@backingInt(descriptor.type)),
        };
        count += 1;
    }
    if (count == 0) return error.InvalidParameter;
    return count;
}

fn enterKernel(entry: u64, info_addr: u32) noreturn {
    asm volatile (
        \\cli
        \\movq %[info], %%rdi
        \\jmpq *%[entry]
        :
        : [info] "r" (@as(u64, info_addr)),
          [entry] "r" (entry),
        : .{ .rdi = true, .memory = true });
    unreachable;
}
