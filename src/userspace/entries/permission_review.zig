const build_options = @import("build_options");
const runtime = @import("userspace_runtime");

export var zigos_userspace_descriptor: runtime.Descriptor align(@alignOf(runtime.Descriptor)) linksection(runtime.ELF_SECTION_NAME) = runtime.initDescriptor(.{
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
export var zigos_userspace_yield_counter: u32 = 0;

pub fn panic(msg: []const u8, trace: ?*runtime.std.builtin.StackTrace, addr: ?usize) noreturn {
    runtime.panic(msg, trace, addr);
}

export fn _start() callconv(.naked) noreturn {
    asm volatile (runtime.startAsm(build_options.heartbeat_increment));
}
