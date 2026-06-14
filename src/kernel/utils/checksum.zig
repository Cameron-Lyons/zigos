pub fn sum8IsZero(bytes: []const u8) bool {
    var sum: u8 = 0;
    for (bytes) |byte| {
        sum +%= byte;
    }
    return sum == 0;
}

pub fn finishSum8(bytes: []u8, checksum_index: usize) void {
    finishSum8Prefix(bytes, checksum_index, bytes.len);
}

pub fn finishSum8Prefix(bytes: []u8, checksum_index: usize, length: usize) void {
    bytes[checksum_index] = 0;
    var sum: u8 = 0;
    for (bytes[0..length]) |byte| {
        sum +%= byte;
    }
    bytes[checksum_index] = 0 -% sum;
}
