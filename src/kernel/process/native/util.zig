pub fn copyText(dest: []u8, src: []const u8) usize {
    const len = @min(dest.len, src.len);
    @memcpy(dest[0..len], src[0..len]);
    return len;
}

pub fn fnv1a64(bytes: []const u8) u64 {
    return fnv1a64WithSeed(0xCBF29CE484222325, bytes);
}

pub fn fnv1a64WithSeed(seed: u64, bytes: []const u8) u64 {
    var hash = seed;
    for (bytes) |byte| {
        hash = fnv1a64AppendByte(hash, byte);
    }
    return hash;
}

pub fn fnv1a64AppendByte(hash: u64, byte: u8) u64 {
    var next = hash;
    next ^= @as(u64, byte);
    next *%= 1099511628211;
    return next;
}

pub fn fnv1a64AppendU64LittleEndian(hash: u64, value: u64) u64 {
    var next = hash;
    var remaining = value;
    inline for (0..8) |_| {
        next = fnv1a64AppendByte(next, @as(u8, @truncate(remaining & 0xFF)));
        remaining >>= 8;
    }
    return next;
}
