const std = @import("std");

pub fn containsIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    if (needle.len == 0) return true;
    if (needle.len > haystack.len) return false;

    var offset: usize = 0;
    while (offset + needle.len <= haystack.len) : (offset += 1) {
        var matched = true;
        for (needle, 0..) |needle_byte, index| {
            if (std.ascii.toLower(haystack[offset + index]) != std.ascii.toLower(needle_byte)) {
                matched = false;
                break;
            }
        }
        if (matched) return true;
    }
    return false;
}
