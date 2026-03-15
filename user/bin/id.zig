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

    stdio.print("uid={d}({s}) gid={d}({s}) euid={d} egid={d}\n", .{ uid, userName(uid), gid, groupName(gid), euid, egid });
    return 0;
}

fn userName(uid: i32) []const u8 {
    return if (uid == 0) "root" else "user";
}

fn groupName(gid: i32) []const u8 {
    return if (gid == 0) "root" else "users";
}
