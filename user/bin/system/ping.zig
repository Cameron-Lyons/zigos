const cstr = @import("cstr");
const ipv4_text = @import("ipv4_text");
const runtime = @import("runtime");
const stdio = @import("stdio");
const syscall = @import("syscall");

pub const panic = runtime.panic;

pub export fn main(argc: usize, argv: [*]const ?[*:0]const u8, envp: [*]const ?[*:0]const u8) callconv(.c) i32 {
    _ = envp;

    if (argc != 2) {
        stdio.eputs("ping: usage: ping <ipv4-address>\n");
        return 1;
    }

    const target = argv[1] orelse return 1;
    const ipv4_addr = ipv4_text.parseIPv4(cstr.slice(target)) orelse {
        stdio.eprint("ping: invalid IPv4 address {s}\n", .{cstr.slice(target)});
        return 1;
    };

    if (syscall.ping(ipv4_addr) != 0) {
        stdio.eprint("ping: failed to send to {s}\n", .{cstr.slice(target)});
        return 1;
    }

    stdio.print("PING {s}\n", .{cstr.slice(target)});
    return 0;
}
