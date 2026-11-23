const console = @import("../utils/console.zig");
const config = @import("../config.zig");
const numfmt = @import("../utils/numfmt.zig");

pub noinline fn printBootMarker(marker: []const u8) void {
    console.print(marker);
    console.print("\n");
}

pub fn printBootProfile() void {
    console.print("BOOT:PROFILE:");
    console.print(config.name());
    console.print("\n");
}

pub fn printKernelRole() void {
    console.print("BOOT:ROLE:");
    console.print(@tagName(config.kernelRole()));
    console.print("\n");
}

pub fn printCpuCount(count: u32) void {
    numfmt.printDec(count);
}
