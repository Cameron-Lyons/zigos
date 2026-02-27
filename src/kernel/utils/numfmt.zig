const vga = @import("../drivers/vga.zig");

pub fn printDec(value: anytype) void {
    var v: u64 = @as(u64, @intCast(value));
    if (v == 0) {
        vga.printChar('0');
        return;
    }

    // SAFETY: populated by the digit extraction loop below.
    var digits: [20]u8 = undefined;
    var count: usize = 0;
    while (v > 0) : (v /= 10) {
        digits[count] = @as(u8, @intCast('0' + (v % 10)));
        count += 1;
    }

    while (count > 0) {
        count -= 1;
        vga.printChar(digits[count]);
    }
}

pub fn printHex(value: anytype) void {
    var v: u64 = @as(u64, @intCast(value));
    if (v == 0) {
        vga.printChar('0');
        return;
    }

    const hex = "0123456789ABCDEF";
    // SAFETY: populated by the nibble extraction loop below.
    var digits: [16]u8 = undefined;
    var count: usize = 0;
    while (v > 0) : (v >>= 4) {
        digits[count] = hex[@as(usize, @intCast(v & 0xF))];
        count += 1;
    }

    while (count > 0) {
        count -= 1;
        vga.printChar(digits[count]);
    }
}
