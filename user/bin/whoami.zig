const account = @import("account");
const runtime = @import("runtime");
const stdio = @import("stdio");
const syscall = @import("syscall");

pub const panic = runtime.panic;

pub export fn main(argc: usize, argv: [*]const ?[*:0]const u8, envp: [*]const ?[*:0]const u8) callconv(.c) i32 {
    _ = argc;
    _ = argv;
    _ = envp;

    var passwd_buffer: [account.MAX_FILE]u8 = undefined;
    const passwd_data = account.loadPasswd(&passwd_buffer) orelse {
        account.printLookupError("whoami");
        return 1;
    };

    const uid: u16 = @intCast(syscall.geteuid());
    const user_name = if (account.findByUid(passwd_data, uid)) |entry| entry.name else "unknown";
    stdio.puts(user_name);
    stdio.puts("\n");
    return 0;
}
