const std = @import("std");
const build_options = @import("build_options");
const userspace_descriptor = @import("userspace_descriptor");
const runtime = @import("userspace_runtime");

pub const EntryMode = union(enum) {
    contract,
    service: runtime.ServiceKind,
};

pub fn Main(comptime mode: EntryMode) type {
    return struct {
        pub const Descriptor = userspace_descriptor.Descriptor;
        pub const descriptor_section = userspace_descriptor.ELF_SECTION_NAME;

        pub fn panic(msg: []const u8, trace: ?*std.builtin.StackTrace, addr: ?usize) noreturn {
            runtime.panic(msg, trace, addr);
        }

        pub fn main() callconv(.c) noreturn {
            switch (mode) {
                .contract => runtime.zigos_userspace_contract_main(
                    build_options.run_mmu_isolation_probe,
                    build_options.run_nx_isolation_probe,
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

        pub fn initDescriptor() Descriptor {
            return userspace_descriptor.initComptime(.{
                .component_class = build_options.component_class,
                .signed = build_options.signed,
                .role_tag = build_options.role_tag,
                .heartbeat_increment = build_options.heartbeat_increment,
                .contract_flags = build_options.contract_flags,
                .bundle_id = build_options.bundle_id,
                .display_name = build_options.display_name,
                .label = build_options.label,
                .entry = build_options.entry,
                .publisher = build_options.publisher,
            });
        }
    };
}
