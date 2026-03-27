const passwd = @import("../../shared/passwd.zig");
const vga = @import("../drivers/vga.zig");
const vfs = @import("../fs/vfs.zig");

pub const MAX_GROUPS: usize = 16;
const PASSWD_BUFFER_SIZE = 2048;

pub const Credentials = struct {
    uid: u16,
    gid: u16,
    euid: u16,
    egid: u16,
    groups: [MAX_GROUPS]u16,
    ngroups: u8,
};

pub const UserEntry = struct {
    uid: u16,
    gid: u16,
    name: [32]u8,
    home: [64]u8,
    active: bool,
};

const MAX_USERS = 64;
var user_table: [MAX_USERS]UserEntry = [_]UserEntry{UserEntry{
    .uid = 0,
    .gid = 0,
    .name = [_]u8{0} ** 32,
    .home = [_]u8{0} ** 64,
    .active = false,
}} ** MAX_USERS;

var uid_lookup: [MAX_USERS]?*UserEntry = [_]?*UserEntry{null} ** MAX_USERS;

var initialized: bool = false;

pub fn init() void {
    if (initialized) return;

    resetUserTable();
    if (loadUsersFromPasswd() == 0) {
        addUserInternal("root", 0, 0, "/root");
        addUserInternal("user", 1000, 1000, "/home/user");
    } else {
        ensureDefaultUser("root", 0, 0, "/root");
        ensureDefaultUser("user", 1000, 1000, "/home/user");
    }

    initialized = true;
    vga.print("Credentials system initialized\n");
}

fn resetUserTable() void {
    for (&user_table) |*entry| {
        entry.* = .{
            .uid = 0,
            .gid = 0,
            .name = [_]u8{0} ** 32,
            .home = [_]u8{0} ** 64,
            .active = false,
        };
    }
    uid_lookup = [_]?*UserEntry{null} ** MAX_USERS;
}

fn addUserInternal(name: []const u8, uid: u16, gid: u16, home: []const u8) void {
    for (&user_table) |*entry| {
        if (!entry.active) {
            entry.uid = uid;
            entry.gid = gid;
            entry.active = true;

            @memset(&entry.name, 0);
            const name_len = @min(name.len, entry.name.len - 1);
            @memcpy(entry.name[0..name_len], name[0..name_len]);

            @memset(&entry.home, 0);
            const home_len = @min(home.len, entry.home.len - 1);
            @memcpy(entry.home[0..home_len], home[0..home_len]);

            uid_lookup[uid % MAX_USERS] = entry;
            return;
        }
    }
}

fn ensureDefaultUser(name: []const u8, uid: u16, gid: u16, home: []const u8) void {
    if (lookupUser(uid) == null) {
        addUserInternal(name, uid, gid, home);
    }
}

fn loadUsersFromPasswd() usize {
    const fd = vfs.open("/etc/passwd", vfs.O_RDONLY) catch return 0;
    defer vfs.close(fd) catch {};

    var buffer: [PASSWD_BUFFER_SIZE]u8 = undefined;
    const bytes_read = vfs.read(fd, buffer[0..]) catch return 0;
    if (bytes_read == 0) return 0;

    var loaded: usize = 0;
    var cursor: usize = 0;
    while (passwd.nextLine(buffer[0..bytes_read], &cursor)) |line| {
        if (passwd.parseLine(line)) |entry| {
            addUserInternal(entry.name, entry.uid, entry.gid, entry.home);
            loaded += 1;
        }
    }

    return loaded;
}

pub fn checkPermission(creds: *const Credentials, mode: vfs.FileMode, file_uid: u16, file_gid: u16, access: u3) bool {
    if (creds.euid == 0) return true;

    if (creds.euid == file_uid) {
        if (access & 4 != 0 and !mode.owner_read) return false;
        if (access & 2 != 0 and !mode.owner_write) return false;
        if (access & 1 != 0 and !mode.owner_exec) return false;
        return true;
    }

    if (creds.egid == file_gid or isInGroup(creds, file_gid)) {
        if (access & 4 != 0 and !mode.group_read) return false;
        if (access & 2 != 0 and !mode.group_write) return false;
        if (access & 1 != 0 and !mode.group_exec) return false;
        return true;
    }

    if (access & 4 != 0 and !mode.other_read) return false;
    if (access & 2 != 0 and !mode.other_write) return false;
    if (access & 1 != 0 and !mode.other_exec) return false;
    return true;
}

fn isInGroup(creds: *const Credentials, gid: u16) bool {
    var i: u8 = 0;
    while (i < creds.ngroups) : (i += 1) {
        if (creds.groups[i] == gid) return true;
    }
    return false;
}

pub fn isRoot(creds: *const Credentials) bool {
    return creds.euid == 0;
}

pub fn lookupUser(uid: u16) ?*UserEntry {
    const slot = uid % MAX_USERS;
    if (uid_lookup[slot]) |entry| {
        if (entry.active and entry.uid == uid) {
            return entry;
        }
    }
    return null;
}

pub fn defaultKernelCredentials() Credentials {
    return Credentials{
        .uid = 0,
        .gid = 0,
        .euid = 0,
        .egid = 0,
        .groups = [_]u16{0} ** MAX_GROUPS,
        .ngroups = 1,
    };
}

pub fn defaultUserCredentials() Credentials {
    return Credentials{
        .uid = 1000,
        .gid = 1000,
        .euid = 1000,
        .egid = 1000,
        .groups = [_]u16{0} ** MAX_GROUPS,
        .ngroups = 1,
    };
}
