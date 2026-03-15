const cstr = @import("cstr");

pub const default_path = "/bin:/usr/bin:/mnt/bin";

pub fn lookup(envp: [*]const ?[*:0]const u8, name: []const u8) ?[]const u8 {
    var i: usize = 0;
    while (true) : (i += 1) {
        const entry_ptr = envp[i] orelse return null;
        const entry = cstr.slice(entry_ptr);
        if (entry.len <= name.len or entry[name.len] != '=') continue;
        if (stdEq(entry[0..name.len], name)) return entry[name.len + 1 ..];
    }
}

fn stdEq(left: []const u8, right: []const u8) bool {
    if (left.len != right.len) return false;
    var i: usize = 0;
    while (i < left.len) : (i += 1) {
        if (left[i] != right[i]) return false;
    }
    return true;
}
