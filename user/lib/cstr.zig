pub fn slice(value: [*:0]const u8) []const u8 {
    var len: usize = 0;
    while (value[len] != 0) : (len += 1) {}
    return value[0..len];
}

pub fn optionalSlice(value: ?[*:0]const u8) []const u8 {
    if (value) |ptr| {
        return slice(ptr);
    }
    return "";
}
