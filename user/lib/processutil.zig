const cstr = @import("cstr");
const syscall = @import("syscall");

pub fn parseSignal(spec: [*:0]const u8) ?i32 {
    const raw = cstr.slice(spec);
    const slice = if (raw.len >= 3 and equalsIgnoreCase(raw[0..3], "SIG")) raw[3..] else raw;
    if (slice.len == 0) return null;

    if (slice[0] >= '0' and slice[0] <= '9') {
        return parsePositiveInt(slice);
    }

    if (equalsIgnoreCase(slice, "INT")) return syscall.SIGINT;
    if (equalsIgnoreCase(slice, "KILL")) return syscall.SIGKILL;
    if (equalsIgnoreCase(slice, "TERM")) return syscall.SIGTERM;
    if (equalsIgnoreCase(slice, "CONT")) return syscall.SIGCONT;
    if (equalsIgnoreCase(slice, "STOP")) return syscall.SIGSTOP;
    if (equalsIgnoreCase(slice, "TSTP")) return syscall.SIGTSTP;
    return null;
}

pub fn parsePid(spec: [*:0]const u8) ?i32 {
    return parsePositiveInt(cstr.slice(spec));
}

fn parsePositiveInt(slice: []const u8) ?i32 {
    if (slice.len == 0) return null;

    var value: i32 = 0;
    for (slice) |char| {
        if (char < '0' or char > '9') return null;
        const digit: i32 = char - '0';
        const next = value * 10 + digit;
        if (next < value) return null;
        value = next;
    }

    return value;
}

fn equalsIgnoreCase(left: []const u8, right: []const u8) bool {
    if (left.len != right.len) return false;

    for (left, right) |l, r| {
        if (asciiUpper(l) != asciiUpper(r)) return false;
    }

    return true;
}

fn asciiUpper(char: u8) u8 {
    if (char >= 'a' and char <= 'z') return char - ('a' - 'A');
    return char;
}
