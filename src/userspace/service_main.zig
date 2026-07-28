const build_options = @import("build_options");
const service_entry = @import("service_entry.zig");
const runtime = @import("userspace_runtime");

const Entry = service_entry.Main(.{ .service = @as(runtime.ServiceKind, @enumFromInt(build_options.service_kind)) });
pub const Descriptor = Entry.Descriptor;
pub const panic = Entry.panic;

export var zigos_userspace_descriptor: Descriptor align(@alignOf(Descriptor)) linksection(Entry.descriptor_section) = Entry.initDescriptor();
export var zigos_userspace_yield_counter: u32 = 0;

export fn zigos_userspace_contract_main() callconv(.c) noreturn {
    Entry.main();
}
