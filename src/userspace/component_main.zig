const service_entry = @import("service_entry.zig");

const Entry = service_entry.Main(.contract);
pub const panic = Entry.panic;

export fn zigos_userspace_contract_main() callconv(.c) noreturn {
    Entry.main();
}
