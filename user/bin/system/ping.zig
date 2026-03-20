const cstr = @import("cstr");
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
    const ipv4_addr = parseIPv4(cstr.slice(target)) orelse {
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

fn parseIPv4(text: []const u8) ?u32 {
    var octets: [4]u32 = undefined;
    var octet_index: usize = 0;
    var current: u32 = 0;
    var saw_digit = false;

    for (text) |char| {
        if (char == '.') {
            if (!saw_digit or octet_index >= octets.len - 1) return null;
            octets[octet_index] = current;
            octet_index += 1;
            current = 0;
            saw_digit = false;
            continue;
        }
        if (char < '0' or char > '9') return null;
        saw_digit = true;
        current = current * 10 + (char - '0');
        if (current > 255) return null;
    }

    if (!saw_digit or octet_index != octets.len - 1) return null;
    octets[octet_index] = current;

    return (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3];
}
