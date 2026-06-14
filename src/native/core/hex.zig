pub const Error = error{
    HexOutputTooSmall,
    InvalidHexDigit,
    InvalidHexLength,
};

const lower_digits = "0123456789abcdef";

pub fn encodedLen(byte_len: usize) usize {
    return byte_len * 2;
}

pub fn encodeLower(bytes: []const u8, output: []u8) Error![]const u8 {
    const output_len = encodedLen(bytes.len);
    if (output.len < output_len) return error.HexOutputTooSmall;

    var cursor: usize = 0;
    for (bytes) |byte| {
        output[cursor] = lowerDigit(byte >> 4);
        output[cursor + 1] = lowerDigit(byte & 0x0f);
        cursor += 2;
    }
    return output[0..output_len];
}

pub fn decodeFixed(comptime len: usize, text: []const u8) Error![len]u8 {
    if (text.len != encodedLen(len)) return error.InvalidHexLength;

    var result: [len]u8 = undefined;
    var index: usize = 0;
    while (index < len) : (index += 1) {
        const high = value(text[index * 2]) orelse return error.InvalidHexDigit;
        const low = value(text[index * 2 + 1]) orelse return error.InvalidHexDigit;
        result[index] = (high << 4) | low;
    }
    return result;
}

pub fn isText(text: []const u8) bool {
    for (text) |byte| {
        if (value(byte) == null) return false;
    }
    return true;
}

pub fn value(byte: u8) ?u8 {
    if (byte >= '0' and byte <= '9') return byte - '0';
    if (byte >= 'a' and byte <= 'f') return byte - 'a' + 10;
    if (byte >= 'A' and byte <= 'F') return byte - 'A' + 10;
    return null;
}

pub fn lowerDigit(nibble: u8) u8 {
    return lower_digits[nibble & 0x0f];
}
