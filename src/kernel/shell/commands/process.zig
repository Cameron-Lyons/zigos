const paging = @import("../../memory/paging.zig");
const timer = @import("../../timer/timer.zig");
const vga = @import("../../drivers/vga.zig");
const numfmt = @import("../../utils/numfmt.zig");

pub fn memInfo() void {
    const stats = paging.getMemoryStats();

    vga.print("Memory Information:\n");
    vga.print("  Total: ");
    numfmt.printDec(stats.total_frames * 4096 / 1024);
    vga.print(" KB\n");
    vga.print("  Used:  ");
    numfmt.printDec(stats.used_frames * 4096 / 1024);
    vga.print(" KB\n");
    vga.print("  Free:  ");
    numfmt.printDec((stats.total_frames - stats.used_frames) * 4096 / 1024);
    vga.print(" KB\n");
}

pub fn uptime() void {
    const ticks = timer.getTicks();
    const seconds = ticks / timer.TICKS_PER_SECOND;
    const minutes = seconds / 60;
    const hours = minutes / 60;

    vga.print("Uptime: ");
    numfmt.printDec(hours);
    vga.print("h ");
    numfmt.printDec(minutes % 60);
    vga.print("m ");
    numfmt.printDec(seconds % 60);
    vga.print("s\n");
}
