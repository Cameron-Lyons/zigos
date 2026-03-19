const std = @import("std");
const stdio = @import("stdio");
const syscall = @import("syscall");

pub const MAX_FILE = 2048;

pub const Account = struct {
    name: []const u8,
    password: []const u8,
    uid: u16,
    gid: u16,
    gecos: []const u8,
    home: []const u8,
    shell: []const u8,
};

pub fn loadPasswd(buffer: []u8) ?[]u8 {
    return loadFile("/etc/passwd", buffer);
}

pub fn findByName(passwd_data: []u8, username: []const u8) ?Account {
    var line_start: usize = 0;
    while (line_start < passwd_data.len) {
        var line_end = line_start;
        while (line_end < passwd_data.len and passwd_data[line_end] != '\n') : (line_end += 1) {}

        const line = trimLine(passwd_data[line_start..line_end]);
        if (parsePasswdLine(line)) |account| {
            if (std.mem.eql(u8, account.name, username)) return account;
        }

        line_start = line_end + 1;
    }

    return null;
}

pub fn findByUid(passwd_data: []u8, uid: u16) ?Account {
    var line_start: usize = 0;
    while (line_start < passwd_data.len) {
        var line_end = line_start;
        while (line_end < passwd_data.len and passwd_data[line_end] != '\n') : (line_end += 1) {}

        const line = trimLine(passwd_data[line_start..line_end]);
        if (parsePasswdLine(line)) |account| {
            if (account.uid == uid) return account;
        }

        line_start = line_end + 1;
    }

    return null;
}

pub fn findGroupName(passwd_data: []u8, gid: u16) ?[]const u8 {
    var line_start: usize = 0;
    while (line_start < passwd_data.len) {
        var line_end = line_start;
        while (line_end < passwd_data.len and passwd_data[line_end] != '\n') : (line_end += 1) {}

        const line = trimLine(passwd_data[line_start..line_end]);
        if (parsePasswdLine(line)) |account| {
            if (account.gid == gid) return account.name;
        }

        line_start = line_end + 1;
    }

    return null;
}

pub fn verifyPassword(account: Account, password: []const u8) bool {
    return std.mem.eql(u8, account.password, password);
}

pub fn printLookupError(tool_name: []const u8) void {
    stdio.eprint("{s}: failed to read /etc/passwd\n", .{tool_name});
}

fn loadFile(path: [*:0]const u8, buffer: []u8) ?[]u8 {
    const fd = syscall.open(path, syscall.O_RDONLY);
    if (syscall.isError(fd)) return null;
    defer _ = syscall.close(fd);

    const rc = syscall.read(fd, buffer);
    if (rc < 0) return null;
    return buffer[0..@intCast(rc)];
}

fn parsePasswdLine(line: []u8) ?Account {
    if (line.len == 0 or line[0] == '#') return null;

    var cursor: usize = 0;
    const name = nextField(line, &cursor) orelse return null;
    const password = nextField(line, &cursor) orelse return null;
    const uid_field = nextField(line, &cursor) orelse return null;
    const gid_field = nextField(line, &cursor) orelse return null;
    const gecos = nextField(line, &cursor) orelse return null;
    const home = nextField(line, &cursor) orelse return null;
    const shell = nextField(line, &cursor) orelse return null;

    if (name.len == 0 or home.len == 0 or shell.len == 0) return null;

    return .{
        .name = name,
        .password = password,
        .uid = std.fmt.parseInt(u16, uid_field, 10) catch return null,
        .gid = std.fmt.parseInt(u16, gid_field, 10) catch return null,
        .gecos = gecos,
        .home = home,
        .shell = shell,
    };
}

fn nextField(line: []u8, cursor: *usize) ?[]u8 {
    if (cursor.* > line.len) return null;

    const start = cursor.*;
    while (cursor.* < line.len and line[cursor.*] != ':') : (cursor.* += 1) {}
    const end = cursor.*;
    if (cursor.* < line.len and line[cursor.*] == ':') cursor.* += 1;
    return line[start..end];
}

fn trimLine(line: []u8) []u8 {
    if (line.len > 0 and line[line.len - 1] == '\r') {
        return line[0 .. line.len - 1];
    }
    return line;
}
