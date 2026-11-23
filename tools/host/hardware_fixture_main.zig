//! Test-only RNUC15CRSU7 proof fixture. It answers as the external hardware and
//! release verifiers, so it is built as its own executable and never as part of
//! zigos-tool. The argv[0] basename selects the verifier role; any other name
//! runs the proof-checker self-test.
const std = @import("std");
const common = @import("common.zig");
const hardware = @import("hardware.zig");
const fixtures = @import("hardware/fixtures.zig");

pub fn main(init: std.process.Init) !void {
    const argv = try init.minimal.args.toSlice(init.arena.allocator());
    var ctx: common.Context = .{ .allocator = init.arena.allocator(), .io = init.io, .environ = init.environ_map };
    const role = std.fs.path.basename(argv[0]);
    run(&ctx, role, argv[1..]) catch |err| {
        std.debug.print("{s}: {s}\n", .{ role, @errorName(err) });
        std.process.exit(1);
    };
}

fn run(ctx: *common.Context, role: []const u8, args: []const []const u8) !void {
    if (std.mem.eql(u8, role, hardware.pinned_verifier_name)) return fixtures.hardwareVerifier(ctx, args);
    if (std.mem.eql(u8, role, hardware.pinned_release_verifier_name)) return fixtures.releaseVerifier(ctx, args);
    if (std.mem.eql(u8, role, fixtures.compiler_name)) return fixtures.compiler(ctx, args);
    if (args.len != 0) return error.InvalidArguments;
    return fixtures.selfTest(ctx);
}
