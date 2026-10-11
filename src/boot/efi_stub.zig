const std = @import("std");
const uefi = std.os.uefi;
const efi_elf = @import("efi_elf.zig");
const efi_handoff = @import("efi_handoff.zig");
const efi_paging = @import("efi_paging.zig");
const payload = @import("boot_payload");
const tcg2 = @import("efi_tcg2.zig");
const cpu_features = @import("../arch/cpu_features.zig");
const x86 = @import("../arch/x86.zig");
const cache_policy = @import("../arch/cache_policy.zig");

pub const NATIVE_EFI_LONG_MODE_ENTRY = true;
pub const DROPS_MULTIBOOT2_PROTECTED_MODE_ENTRY = true;

const HANDOFF_PAGES: usize = 8;
const MMAP_ENTRY_CAP: usize = 256;
const RSDP_CAP: usize = 64;
const HANDOFF_MAX_ADDRESS: usize = 128 * 1024 * 1024;
const PAGING_SIZING_ATTEMPTS: usize = 8;
var firmware_console_available = true;

pub fn main() uefi.Status {
    const system_table = uefi.system_table;
    const boot = system_table.boot_services orelse return .unsupported;
    // This stub is compiled for baseline x86-64. Reject missing native
    // instructions/state while firmware diagnostics work; XCR0 setup belongs
    // to the assembly entry after ExitBootServices, before generated code.
    const features = cpu_features.detect();
    if (cpu_features.baseline.firstMissingCodegen(features) != null) {
        return bootFailure("cpu-codegen-baseline", .unsupported);
    }
    cpu_features.validateBootstrapCache() catch |err| return cacheAdmissionFailure(err);
    if (!features.nx) return bootFailure("cpu-nx", .unsupported);
    var frozen_cache: cache_policy.MtrrState = undefined;
    x86.readMtrrStateInto(&frozen_cache) catch return bootFailure("cache-mtrr-state", .unsupported);
    frozen_cache.validateWritable() catch return bootFailure("cache-mtrr-operands", .unsupported);
    const cache_view = cache_policy.ValidatedMtrrView.init(&frozen_cache) catch return bootFailure("cache-mtrr-policy", .unsupported);
    if (!payload.isolated_low_proof and !features.pages_1g) return bootFailure("cpu-pages-1g", .unsupported);
    boot.setWatchdogTimer(0, 0, null) catch {};

    const kernel_bytes = payload.kernel;
    const image = efi_elf.parseForMode(kernel_bytes, if (payload.isolated_low_proof) .isolated_low_proof else .native_high) catch return .incompatible_version;
    const cmdline = efi_handoff.embeddedCommandLine(payload.cmdline) catch return .invalid_parameter;
    const authenticated = firmwareAuthenticated(system_table);

    const gop = readFramebuffer(boot) catch return bootFailure("framebuffer-extent", .unsupported);
    const framebuffer = gop.framebuffer;
    const framebuffer_span = (efi_handoff.paging_info.Info{
        .transition_base = 0,
        .transition_pages = 0,
        .final_base = 0,
        .final_pages = 0,
        .framebuffer_base = gop.base,
        .framebuffer_bytes = gop.bytes,
    }).framebufferSpan() catch return bootFailure("framebuffer-extent", .unsupported);
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
        requireOutsideFramebuffer(framebuffer_span, segment.phys_addr, segment.pageCount() * 4096) catch
            return bootFailure("kernel-framebuffer-overlap", .unsupported);
        _ = boot.allocatePages(.{ .address = @ptrFromInt(@as(usize, @intCast(segment.phys_addr))) }, .loader_code, segment.pageCount()) catch {
            reportReservationConflict(boot, segment);
            return bootFailure("kernel-reservation", .out_of_resources);
        };
        reserved += 1;
        cache_view.requireWriteBack(segment.phys_addr, segment.pageCount() * 4096) catch return bootFailure("kernel-cache-policy", .unsupported);
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
    requireOutsideFramebuffer(framebuffer_span, @intFromPtr(heap_pages.ptr), heap_pages.len * 4096) catch
        return bootFailure("heap-framebuffer-overlap", .unsupported);
    cache_view.requireWriteBack(@intFromPtr(heap_pages.ptr), heap_pages.len * 4096) catch return bootFailure("heap-cache-policy", .unsupported);

    // All other loader allocations precede table sizing, including the final
    // TPM log and handoff. The active firmware root remains untouched.
    efi_paging.validateTransition(readCr4(), @intFromPtr(&enterKernel), readStackPointer()) catch
        return bootFailure("paging-transition", .unsupported);
    const boot_image = efi_handoff.image_info.Info.measure(kernel_bytes, cmdline, authenticated, @intFromPtr(heap_pages.ptr));
    var measurement = tcg2.capture(boot, system_table, boot_image, cache_view, framebuffer_span) catch return bootFailure("tpm-measurement", .security_violation);
    defer if (measurement) |captured| boot.freePages(captured.pages) catch {};

    const handoff_pages = boot.allocatePages(
        .{ .max_address = @ptrFromInt(HANDOFF_MAX_ADDRESS) },
        .loader_data,
        HANDOFF_PAGES,
    ) catch return bootFailure("handoff-reservation", .out_of_resources);
    defer boot.freePages(handoff_pages) catch {};
    requireOutsideFramebuffer(framebuffer_span, @intFromPtr(handoff_pages.ptr), handoff_pages.len * 4096) catch
        return bootFailure("handoff-framebuffer-overlap", .unsupported);
    cache_view.requireWriteBack(@intFromPtr(handoff_pages.ptr), handoff_pages.len * 4096) catch return bootFailure("handoff-cache-policy", .unsupported);
    const handoff_bytes: []u8 = @as([*]u8, @ptrCast(handoff_pages.ptr))[0 .. HANDOFF_PAGES * 4096];
    const info_addr: u32 = @intCast(@intFromPtr(handoff_bytes.ptr));

    var mmap_entries: [MMAP_ENTRY_CAP]efi_handoff.MmapEntry = undefined;
    var raw_map = allocateMapBuffer(boot, cache_view, framebuffer_span) catch return bootFailure("map-reservation", .out_of_resources);
    defer boot.freePool(raw_map.ptr) catch {};
    var bootstrap_pages: ?[]align(4096) uefi.Page = null;
    defer if (bootstrap_pages) |pages| boot.freePages(pages) catch {};
    var final_pages: ?[]align(4096) uefi.Page = null;
    defer if (final_pages) |pages| boot.freePages(pages) catch {};
    var paging_info: ?efi_handoff.paging_info.Info = null;
    var sizing_ready = false;
    const transition_mode: efi_paging.Mode = if (payload.isolated_low_proof) .isolated_low_proof else .native_high;
    // Allocations can split or move EFI descriptors. Count their resulting map
    // again before accepting capacity; growth is bounded and stays before the
    // first ExitBootServices call. No seed allocation reserves the maximum.
    for (0..PAGING_SIZING_ATTEMPTS) |_| {
        const map_slice = boot.getMemoryMap(raw_map) catch |err| switch (err) {
            error.BufferTooSmall => {
                const replacement = allocateMapBuffer(boot, cache_view, framebuffer_span) catch return bootFailure("map-reservation", .out_of_resources);
                boot.freePool(raw_map.ptr) catch {
                    boot.freePool(replacement.ptr) catch {};
                    return bootFailure("map-release", .out_of_resources);
                };
                raw_map = replacement;
                continue;
            },
            else => return bootFailure("map-read", .out_of_resources),
        };
        const mmap_count = captureMemoryMap(map_slice, &mmap_entries, paging_info, framebuffer_span) catch return bootFailure("map-invalid", .out_of_resources);
        const needed = countPagingArenas(transition_mode, image, mmap_entries[0..mmap_count], cache_view, boot_image.heap_base, framebuffer_span) catch return bootFailure("paging-count", .out_of_resources);
        if (bootstrap_pages != null and final_pages != null and needed.fits(bootstrap_pages.?.len, final_pages.?.len)) {
            sizing_ready = true;
            break;
        }
        // Nothing references these inactive arenas yet. Clear each ownership
        // slot after a successful free, so a failed replacement cannot double
        // free a stale receipt while unwinding.
        if (bootstrap_pages == null or bootstrap_pages.?.len < needed.transition) {
            if (bootstrap_pages) |pages| {
                boot.freePages(pages) catch return bootFailure("paging-release", .out_of_resources);
                bootstrap_pages = null;
            }
            bootstrap_pages = allocatePagingArena(boot, needed.transition, cache_view, framebuffer_span) catch return bootFailure("paging-reservation", .out_of_resources);
        }
        if (final_pages == null or final_pages.?.len < needed.final) {
            if (final_pages) |pages| {
                boot.freePages(pages) catch return bootFailure("final-paging-release", .out_of_resources);
                final_pages = null;
            }
            final_pages = allocatePagingArena(boot, needed.final, cache_view, framebuffer_span) catch return bootFailure("final-paging-reservation", .out_of_resources);
        }
        paging_info = .{
            .transition_base = @intFromPtr(bootstrap_pages.?.ptr),
            .transition_pages = @intCast(bootstrap_pages.?.len),
            .final_base = @intFromPtr(final_pages.?.ptr),
            .final_pages = @intCast(final_pages.?.len),
            .framebuffer_base = gop.base,
            .framebuffer_bytes = gop.bytes,
        };
        paging_info.?.validate() catch return bootFailure("paging-ownership", .out_of_resources);
    }
    if (!sizing_ready) return bootFailure("paging-sizing-limit", .out_of_resources);
    const arenas = paging_info.?;
    const bootstrap_physical = arenas.transition_base;
    // Build the complete handoff before leaving firmware. If a firmware exit
    // notification changes the map, refresh it in the same allocation and retry.
    for (0..2) |attempt| {
        const map_slice = boot.getMemoryMap(raw_map) catch {
            if (attempt != 0) return .out_of_resources;
            return bootFailure("map-read", .out_of_resources);
        };
        const mmap_count = captureMemoryMap(map_slice, &mmap_entries, arenas, framebuffer_span) catch |err| {
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
            .boot_paging = arenas,
        };
        for (image.segments[0..image.segment_count]) |segment| {
            efi_paging.requireRamRange(request.mmap, segment.phys_addr, segment.pageCount() * 4096) catch return bootFailure("kernel-ram-ownership", .unsupported);
        }
        efi_paging.requireRamRange(request.mmap, arenas.transition_base, arenas.transitionBytes()) catch return bootFailure("paging-ram-ownership", .unsupported);
        efi_paging.requireRamRange(request.mmap, arenas.final_base, arenas.finalBytes()) catch return bootFailure("paging-ram-ownership", .unsupported);
        const needed = countPagingArenas(transition_mode, image, request.mmap, cache_view, boot_image.heap_base, framebuffer_span) catch return bootFailure("paging-count", .out_of_resources);
        if (!needed.fits(arenas.transition_pages, arenas.final_pages)) return bootFailure("paging-capacity-changed", .out_of_resources);
        efi_paging.requireRamRange(request.mmap, boot_image.heap_base, efi_handoff.image_info.KERNEL_HEAP_BYTES) catch return bootFailure("heap-ram-ownership", .unsupported);
        efi_paging.requireRamRange(request.mmap, info_addr, HANDOFF_PAGES * 4096) catch return bootFailure("handoff-ram-ownership", .unsupported);
        if (measurement) |captured| efi_paging.requireRamRange(request.mmap, captured.info.log_address, captured.pages.len * 4096) catch return bootFailure("tpm-ram-ownership", .unsupported);
        _ = efi_handoff.encode(handoff_bytes, request) catch return .load_error;
        // The last firmware calls can change privileged CPU state. Admission
        // owns the full selector contract before creating any native alias.
        cpu_features.validateBootstrapCache() catch |err| return cacheAdmissionFailure(err);
        var current_cache: cache_policy.MtrrState = undefined;
        x86.readMtrrStateInto(&current_cache) catch return bootFailure("cache-mtrr-state", .unsupported);
        if (!frozen_cache.sameConfiguration(&current_cache)) return bootFailure("cache-policy-changed", .unsupported);
        const pre_exit_root: *const [512]u64 = @ptrFromInt(readCr3() & efi_paging.PHYSICAL_ADDRESS_MASK);
        _ = efi_paging.buildForMode(bootstrap_pages.?, bootstrap_physical, pre_exit_root, transition_mode, image, request.mmap, cache_view, boot_image.heap_base, arenas) catch return bootFailure("paging-bootstrap", .unsupported);
        firmware_console_available = false;
        boot.exitBootServices(uefi.handle, map_slice.info.key) catch continue;
        // No firmware calls or allocations after this point. Keep the firmware
        // mappings until its final events have been copied into owned low pages.
        asm volatile ("cli" ::: .{ .memory = true });
        if (measurement) |*captured| {
            captured.finish(boot_image) catch haltAfterExit("tpm-final-events");
            request.boot_tpm = captured.info;
            // This exact-sized encoding already succeeded before firmware exit.
            _ = efi_handoff.encode(handoff_bytes, request) catch haltAfterExit("tpm-final-events");
        }
        cpu_features.validateBootstrapCache() catch |err| switch (err) {
            error.PatUnsupported => haltAfterExit("cache-pat-unsupported"),
            error.CacheDisabled => haltAfterExit("cache-controls-disabled"),
            error.InvalidPatEncoding => haltAfterExit("cache-pat-encoding"),
            error.UnsupportedPatLayout => haltAfterExit("cache-pat-layout"),
        };
        x86.readMtrrStateInto(&current_cache) catch haltAfterExit("cache-mtrr-state");
        if (!frozen_cache.sameConfiguration(&current_cache)) haltAfterExit("cache-policy-changed");
        const active_root: *const [512]u64 = @ptrFromInt(readCr3() & efi_paging.PHYSICAL_ADDRESS_MASK);
        const bootstrap_cr3 = efi_paging.buildForMode(bootstrap_pages.?, bootstrap_physical, active_root, transition_mode, image, mmap_entries[0..mmap_count], cache_view, boot_image.heap_base, arenas) catch haltAfterExit("paging-bootstrap");
        x86.enableNoExecute();
        x86.writeCr0(x86.readCr0() | x86.CR0_WP);
        if (x86.readCr0() & x86.CR0_WP == 0) haltAfterExit("write-protect");
        enterKernel(image.entry, info_addr, bootstrap_cr3);
    }
    return .aborted;
}

const PagingNeeds = struct {
    transition: usize,
    final: usize,

    inline fn fits(self: PagingNeeds, transition: usize, final: usize) bool {
        return self.transition <= transition and self.final <= final;
    }
};

fn countPagingArenas(mode: efi_paging.Mode, image: efi_elf.Image, entries: []const efi_handoff.MmapEntry, cache: cache_policy.ValidatedMtrrView, heap_base: u64, framebuffer_span: ?efi_handoff.paging_info.Span) !PagingNeeds {
    var transition: efi_paging.sparse.Counts = undefined;
    try efi_paging.countForModeInto(mode, image, entries, cache, heap_base, framebuffer_span, &transition);
    var final = transition;
    if (mode != .native_high) try efi_paging.countForModeInto(.native_high, image, entries, cache, heap_base, framebuffer_span, &final);
    if (transition.used_pages < 3 or transition.used_pages > efi_paging.MAX_PAGE_COUNT or final.used_pages < 3 or final.used_pages > efi_paging.MAX_PAGE_COUNT)
        return error.InvalidArena;
    return .{ .transition = transition.used_pages, .final = final.used_pages };
}

fn allocatePagingArena(boot: *uefi.tables.BootServices, count: usize, cache: cache_policy.ValidatedMtrrView, framebuffer_span: ?efi_handoff.paging_info.Span) ![]align(4096) uefi.Page {
    if (count < 3 or count > efi_paging.MAX_PAGE_COUNT) return error.InvalidArena;
    const pages = try boot.allocatePages(.{ .max_address = @ptrFromInt(efi_paging.ALIAS_BYTES - efi_paging.PAGE_BYTES) }, .loader_data, count);
    errdefer boot.freePages(pages) catch {};
    try requireOutsideFramebuffer(framebuffer_span, @intFromPtr(pages.ptr), pages.len * 4096);
    try cache.requireWriteBack(@intFromPtr(pages.ptr), pages.len * 4096);
    return pages;
}

fn allocateMapBuffer(boot: *uefi.tables.BootServices, cache: cache_policy.ValidatedMtrrView, framebuffer_span: ?efi_handoff.paging_info.Span) ![]align(@alignOf(uefi.tables.MemoryDescriptor)) u8 {
    const info = try boot.getMemoryMapInfo();
    if (info.len > MMAP_ENTRY_CAP or info.descriptor_size < @sizeOf(uefi.tables.MemoryDescriptor) or info.descriptor_size > 4096)
        return error.BufferTooSmall;
    // Two paging allocations can split descriptors. Keep bounded space for
    // those changes and exit notifications without a post-exit allocation.
    const count = try std.math.add(usize, info.len, 16);
    const bytes = try std.math.mul(usize, count, info.descriptor_size);
    const raw = try boot.allocatePool(.loader_data, bytes);
    errdefer boot.freePool(raw.ptr) catch {};
    try requireOutsideFramebuffer(framebuffer_span, @intFromPtr(raw.ptr), raw.len);
    try cache.requireWriteBack(@intFromPtr(raw.ptr), raw.len);
    return @alignCast(raw);
}

fn haltAfterExit(comptime stage: []const u8) noreturn {
    // The firmware console is gone. Report through the x86 debug serial port
    // with a bounded wait, then stop without running boot-service defers.
    for ("EFI:FAIL:" ++ stage ++ "\r\n") |byte| {
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

inline fn cacheAdmissionFailure(err: cpu_features.cache_policy.AdmissionError) uefi.Status {
    return switch (err) {
        error.PatUnsupported => bootFailure("cache-pat-unsupported", .unsupported),
        error.CacheDisabled => bootFailure("cache-controls-disabled", .unsupported),
        error.InvalidPatEncoding => bootFailure("cache-pat-encoding", .unsupported),
        error.UnsupportedPatLayout => bootFailure("cache-pat-layout", .unsupported),
    };
}

fn bootFailure(comptime stage: []const u8, status: uefi.Status) uefi.Status {
    if (!firmware_console_available) return status;
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

const GopCapture = struct {
    framebuffer: ?efi_handoff.Framebuffer = null,
    base: u64 = 0,
    bytes: u64 = 0,
};

fn readFramebuffer(boot: *uefi.tables.BootServices) !GopCapture {
    const gop = boot.locateProtocol(uefi.protocol.GraphicsOutput, null) catch return .{};
    const protocol = gop orelse return .{};
    const mode = protocol.mode;
    var result = GopCapture{ .base = mode.frame_buffer_base, .bytes = mode.frame_buffer_size };
    // Ownership survives unsupported render formats and includes the full
    // allocation advertised by GOP, including padding beyond visible pixels.
    _ = try (efi_handoff.paging_info.Info{ .transition_base = 0, .transition_pages = 0, .final_base = 0, .final_pages = 0, .framebuffer_base = result.base, .framebuffer_bytes = result.bytes }).framebufferSpan();
    if (result.bytes == 0) return result;
    const info = mode.info;
    if (info.horizontal_resolution == 0 or info.vertical_resolution == 0) return result;
    const rgb = switch (info.pixel_format) {
        .red_green_blue_reserved_8_bit_per_color => efi_handoff.rgbFromMasks(0, 8, 16),
        .blue_green_red_reserved_8_bit_per_color => efi_handoff.rgbFromMasks(16, 8, 0),
        else => return result,
    };
    const pitch = try std.math.mul(u32, info.pixels_per_scan_line, 4);
    const visible_bytes = try std.math.mul(u64, pitch, info.vertical_resolution);
    if (info.pixels_per_scan_line < info.horizontal_resolution or visible_bytes > result.bytes) return error.InvalidFramebuffer;
    result.framebuffer = .{
        .addr = mode.frame_buffer_base,
        .pitch = pitch,
        .width = info.horizontal_resolution,
        .height = info.vertical_resolution,
        .rgb = rgb,
    };
    return result;
}

fn requireOutsideFramebuffer(span: ?efi_handoff.paging_info.Span, start: u64, bytes: u64) error{InvalidFramebuffer}!void {
    const device = span orelse return;
    const end = std.math.add(u64, start, bytes) catch return error.InvalidFramebuffer;
    if (start < device.end and device.start < end) return error.InvalidFramebuffer;
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
    paging_info: ?efi_handoff.paging_info.Info,
    framebuffer_span: ?efi_handoff.paging_info.Span,
) !usize {
    var count: usize = 0;
    var iterator = slice.iterator();
    while (iterator.next()) |descriptor| {
        const pages = descriptor.number_of_pages;
        const length = try std.math.mul(u64, pages, 4096);
        if (length == 0) continue;
        try efi_paging.appendMemoryDescriptor(entries, &count, descriptor.physical_start, length, efi_handoff.kindFromEfiMemoryType(@backingInt(descriptor.type)), @backingInt(descriptor.type), @as(u64, @bitCast(descriptor.attribute)), paging_info);
    }
    if (count == 0) return error.InvalidParameter;
    efi_paging.sortEntries(entries[0..count]);
    var regions: [256]efi_paging.sparse.Region = undefined;
    _ = try efi_paging.ramRegions(entries[0..count], &regions, framebuffer_span);
    return count;
}

fn readCr3() u64 {
    return asm volatile ("movq %%cr3, %[value]"
        : [value] "=r" (-> u64),
    );
}

fn readCr4() u64 {
    return asm volatile ("movq %%cr4, %[value]"
        : [value] "=r" (-> u64),
    );
}

fn readStackPointer() u64 {
    return asm volatile ("movq %%rsp, %[value]"
        : [value] "=r" (-> u64),
    );
}

fn enterKernel(entry: u64, info_addr: u32, physical_cr3: u64) noreturn {
    asm volatile (
        \\cli
        \\movq %%cr4, %%rax
        \\movq %%rax, %%rcx
        \\andq $-129, %%rcx
        \\movq %%rcx, %%cr4
        \\movq %[root], %%cr3
        \\movq %%rax, %%cr4
        \\movq %[info], %%rdi
        \\jmpq *%[entry]
        :
        : [info] "r" (@as(u64, info_addr)),
          [entry] "r" (entry),
          [root] "r" (physical_cr3),
        : .{ .rax = true, .rcx = true, .rdi = true, .memory = true });
    unreachable;
}
