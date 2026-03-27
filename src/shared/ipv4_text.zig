pub fn parseIPv4(text: []const u8) ?u32 {
    var ip: u32 = 0;
    var octet: u32 = 0;
    var octet_count: u8 = 0;
    var saw_digit = false;

    for (text) |char| {
        if (char == '.') {
            if (!saw_digit or octet > 255 or octet_count >= 3) return null;
            ip = (ip << 8) | octet;
            octet = 0;
            octet_count += 1;
            saw_digit = false;
            continue;
        }

        if (char < '0' or char > '9') return null;
        saw_digit = true;
        octet = octet * 10 + (char - '0');
        if (octet > 255) return null;
    }

    if (!saw_digit or octet_count != 3 or octet > 255) return null;
    return (ip << 8) | octet;
}
