const dispatch = @import("dispatch.zig");

pub fn getCwd() []const u8 {
    return dispatch.getCwd();
}

pub fn setCwd(path: []const u8) bool {
    return dispatch.setCwd(path);
}

pub fn getHostname() []const u8 {
    return dispatch.getHostname();
}

pub fn setHostname(name: []const u8) void {
    dispatch.setHostname(name);
}
