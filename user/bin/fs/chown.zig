const account = @import("account");
const cstr = @import("cstr");
const runtime = @import("runtime");
const std = @import("std");
const stdio = @import("stdio");
const syscall = @import("syscall");

pub const panic = runtime.panic;

const ChangeSpec = struct {
    owner: i32,
    group: i32,
};

fn resolveUid(passwd_data: []u8, spec: []const u8) ?u16 {
    if (spec.len == 0) return null;
    return std.fmt.parseInt(u16, spec, 10) catch blk: {
        const entry = account.findByName(passwd_data, spec) orelse break :blk null;
        break :blk entry.uid;
    };
}

fn resolveGid(passwd_data: []u8, spec: []const u8) ?u16 {
    if (spec.len == 0) return null;
    return std.fmt.parseInt(u16, spec, 10) catch blk: {
        const entry = account.findByName(passwd_data, spec) orelse break :blk null;
        break :blk entry.gid;
    };
}

fn parseChangeSpec(passwd_data: []u8, text: []const u8) ?ChangeSpec {
    const separator = std.mem.indexOfScalar(u8, text, ':');
    const owner_text = if (separator) |index| text[0..index] else text;
    const group_text = if (separator) |index| text[index + 1 ..] else "";
    const has_group = separator != null;

    const owner_value: i32 = if (owner_text.len == 0)
        -1
    else
        resolveUid(passwd_data, owner_text) orelse return null;
    const group_value: i32 = if (!has_group or group_text.len == 0)
        -1
    else
        resolveGid(passwd_data, group_text) orelse return null;

    if (owner_value < 0 and group_value < 0) return null;
    return .{
        .owner = owner_value,
        .group = group_value,
    };
}

pub export fn main(argc: usize, argv: [*]const ?[*:0]const u8, envp: [*]const ?[*:0]const u8) callconv(.c) i32 {
    _ = envp;

    if (argc < 3) {
        stdio.eputs("chown: usage: chown <owner[:group]> <path> [path ...]\n");
        return 1;
    }

    var passwd_buffer: [account.MAX_FILE]u8 = undefined;
    const passwd_data = account.loadPasswd(&passwd_buffer) orelse {
        account.printLookupError("chown");
        return 1;
    };

    const change_spec_text = cstr.slice(argv[1] orelse return 1);
    const change_spec = parseChangeSpec(passwd_data, change_spec_text) orelse {
        stdio.eputs("chown: invalid owner or group\n");
        return 1;
    };

    var exit_code: i32 = 0;
    var i: usize = 2;
    while (i < argc) : (i += 1) {
        const path = argv[i] orelse continue;
        if (syscall.fchownat(syscall.AT_FDCWD, path, change_spec.owner, change_spec.group) != 0) {
            stdio.eprint("chown: failed to change owner on {s}\n", .{cstr.slice(path)});
            exit_code = 1;
        }
    }

    return exit_code;
}
