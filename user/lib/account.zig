const std = @import("std");
const fsutil = @import("fsutil");
const passwd = @import("passwd_shared");
const stdio = @import("stdio");

pub const MAX_FILE = 2048;

pub const Account = passwd.Entry;

pub fn loadPasswd(buffer: []u8) ?[]u8 {
    return fsutil.readFile("/etc/passwd", buffer) catch null;
}

pub fn findByName(passwd_data: []const u8, username: []const u8) ?Account {
    var cursor: usize = 0;
    while (passwd.nextLine(passwd_data, &cursor)) |line| {
        if (passwd.parseLine(line)) |account| {
            if (std.mem.eql(u8, account.name, username)) return account;
        }
    }

    return null;
}

pub fn findByUid(passwd_data: []const u8, uid: u16) ?Account {
    var cursor: usize = 0;
    while (passwd.nextLine(passwd_data, &cursor)) |line| {
        if (passwd.parseLine(line)) |account| {
            if (account.uid == uid) return account;
        }
    }

    return null;
}

pub fn findGroupName(passwd_data: []const u8, gid: u16) ?[]const u8 {
    var cursor: usize = 0;
    while (passwd.nextLine(passwd_data, &cursor)) |line| {
        if (passwd.parseLine(line)) |account| {
            if (account.gid == gid) return account.name;
        }
    }

    return null;
}

pub fn verifyPassword(account: Account, password: []const u8) bool {
    return std.mem.eql(u8, account.password, password);
}

pub fn printLookupError(tool_name: []const u8) void {
    stdio.eprint("{s}: failed to read /etc/passwd\n", .{tool_name});
}
