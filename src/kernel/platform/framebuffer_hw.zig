const std = @import("std");
const builtin = @import("builtin");
const framebuffer = @import("framebuffer.zig");
const handoff = @import("../boot/handoff.zig");
const mmio = @import("../memory/mmio_windows.zig");
const paging = @import("../memory/paging64.zig");
const table64 = @import("../memory/page_table64.zig");
const scanout = @import("text_scanout.zig");

var renderer: scanout.Renderer = undefined;
var composed_frame: scanout.Frame = undefined;
var initialized = false;

pub const Mapping = struct {
    physical_base: usize,
    page_bytes: usize,
    pixel_offset: usize,
    pixel_count: usize,
};

pub fn mappingFor(info: framebuffer.Info) !Mapping {
    _ = try framebuffer.validate(info);
    const bytes = try info.minimumBufferBytes();
    const last = std.math.add(u64, info.physical_address, bytes - 1) catch return error.InvalidAddress;
    if (!table64.physicalAddressFits(last)) return error.InvalidAddress;
    const physical: usize = @intCast(info.physical_address);
    const offset = physical % mmio.PAGE_BYTES;
    const extent = std.math.add(usize, @intCast(bytes), offset + mmio.PAGE_BYTES - 1) catch return error.BufferTooLarge;
    const page_bytes = extent & ~(mmio.PAGE_BYTES - 1);
    if (page_bytes > mmio.framebuffer.bytes) return error.BufferTooLarge;
    return .{
        .physical_base = physical - offset,
        .page_bytes = page_bytes,
        .pixel_offset = offset,
        .pixel_count = @intCast(bytes / 4),
    };
}

// Boot CPU only, after paging initialization and before creating user address
// spaces. The mapping is supervisor-only, non-executable and uncached. The
// caller retains sole ownership; there is no raw-framebuffer userspace handle.
pub fn init() !void {
    if (comptime builtin.os.tag != .freestanding) return error.Unavailable;
    if (initialized) return;
    const boot = handoff.capturedInfo() orelse return error.MissingFramebuffer;
    const info = try handoff.framebufferInfo(boot);
    const mapping = try mappingFor(info);
    var offset: usize = 0;
    while (offset < mapping.page_bytes) : (offset += mmio.PAGE_BYTES) {
        paging.mapKernelBorrowedPage(
            mmio.framebuffer.base + offset,
            mapping.physical_base + offset,
            paging.PAGE_PRESENT | paging.PAGE_WRITABLE | paging.PAGE_CACHE_DISABLE | paging.PAGE_WRITE_THROUGH,
        );
    }
    const pixels: [*]volatile u32 = @ptrFromInt(mmio.framebuffer.base + mapping.pixel_offset);
    renderer = try scanout.Renderer.init(info, pixels[0..mapping.pixel_count]);
    composed_frame = try scanout.Frame.init(renderer.columns, renderer.rows);
    initialized = true;
}

pub fn frame() ?*scanout.Frame {
    return if (initialized) &composed_frame else null;
}

pub fn present() !scanout.PresentStats {
    if (!initialized) return error.Unavailable;
    return renderer.present(&composed_frame);
}

pub fn displayInfo() ?framebuffer.Info {
    return if (initialized) renderer.info else null;
}
