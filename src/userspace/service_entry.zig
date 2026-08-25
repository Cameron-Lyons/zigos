const std = @import("std");
const build_options = @import("build_options");
const runtime = @import("userspace_runtime");

pub export const zigos_userspace_role_identity: [8]u8 align(1) linksection(".zigos_userspace_role_identity") = .{
    'Z',
    'R',
    'O',
    'L',
    @truncate(build_options.role_tag),
    @truncate(build_options.role_tag >> 8),
    @truncate(build_options.role_tag >> 16),
    @truncate(build_options.role_tag >> 24),
};

pub const EntryMode = union(enum) {
    contract,
    service: runtime.ServiceKind,
};

pub fn Main(comptime mode: EntryMode) type {
    return struct {
        pub fn panic(msg: []const u8, trace: ?*std.builtin.StackTrace, addr: ?usize) noreturn {
            runtime.panic(msg, trace, addr);
        }

        pub fn main() callconv(.c) noreturn {
            switch (mode) {
                .contract => runtime.zigos_userspace_contract_main(
                    build_options.run_mmu_isolation_probe,
                    build_options.run_nx_isolation_probe,
                    build_options.run_gp_isolation_probe,
                    build_options.bundle_id,
                    build_options.contract_flags,
                ),
                .service => |service_kind| runtime.zigos_userspace_service_main(
                    service_kind,
                    build_options.bundle_id,
                    build_options.contract_flags,
                ),
            }
        }
    };
}
