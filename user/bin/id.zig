const account = @import("account");
const runtime = @import("runtime");
const stdio = @import("stdio");
const syscall = @import("syscall");

pub const panic = runtime.panic;

pub export fn main(argc: usize, argv: [*]const ?[*:0]const u8, envp: [*]const ?[*:0]const u8) callconv(.c) i32 {
    _ = argc;
    _ = argv;
    _ = envp;

    const uid = syscall.getuid();
    const gid = syscall.getgid();
    const euid = syscall.geteuid();
    const egid = syscall.getegid();

    var passwd_buffer: [account.MAX_FILE]u8 = undefined;
    const passwd_data = account.loadPasswd(&passwd_buffer) orelse {
        account.printLookupError("id");
        return 1;
    };

    const uid_name = if (account.findByUid(passwd_data, @intCast(uid))) |entry| entry.name else "unknown";
    const gid_name = account.findGroupName(passwd_data, @intCast(gid)) orelse "unknown";
    const euid_name = if (account.findByUid(passwd_data, @intCast(euid))) |entry| entry.name else "unknown";
    const egid_name = account.findGroupName(passwd_data, @intCast(egid)) orelse "unknown";

    stdio.print("uid={d}({s}) gid={d}({s}) euid={d}({s}) egid={d}({s})\n", .{ uid, uid_name, gid, gid_name, euid, euid_name, egid, egid_name });
    return 0;
}
