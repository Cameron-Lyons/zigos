const build_options = @import("build_options");
const service_entry = @import("service_entry.zig");
const runtime = @import("userspace_runtime");

const Entry = service_entry.Main(.{ .service = @as(runtime.ServiceKind, @fromBackingInt(@intCast(build_options.service_kind))) });
pub const panic = Entry.panic;

export fn zigos_userspace_contract_main() callconv(.c) noreturn {
    Entry.main();
}
