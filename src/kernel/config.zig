const build_options = @import("build_options");

pub const BootProfile = @TypeOf(build_options.boot_profile);

const ProfileSettings = struct {
    name: []const u8,
    init_acpi: bool,
    init_smp: bool,
    init_network_stack: bool,
    init_runtime_extras: bool,
    exit_on_completion: bool,
};

pub fn bootProfile() BootProfile {
    return build_options.boot_profile;
}

fn settings() ProfileSettings {
    return switch (bootProfile()) {
        .dev => .{
            .name = "dev",
            .init_acpi = true,
            .init_smp = true,
            .init_network_stack = true,
            .init_runtime_extras = true,
            .exit_on_completion = false,
        },
        .ci_smoke => .{
            .name = "ci_smoke",
            .init_acpi = false,
            .init_smp = false,
            .init_network_stack = false,
            .init_runtime_extras = false,
            .exit_on_completion = true,
        },
        .test_vm => .{
            .name = "test_vm",
            .init_acpi = false,
            .init_smp = false,
            .init_network_stack = false,
            .init_runtime_extras = false,
            .exit_on_completion = true,
        },
        .userland_smoke => .{
            .name = "userland_smoke",
            .init_acpi = false,
            .init_smp = false,
            .init_network_stack = false,
            .init_runtime_extras = false,
            .exit_on_completion = true,
        },
    };
}

pub fn name() []const u8 {
    return settings().name;
}

pub fn shouldInitAcpi() bool {
    return settings().init_acpi;
}

pub fn shouldInitSmp() bool {
    return settings().init_smp;
}

pub fn shouldInitNetworkStack() bool {
    return settings().init_network_stack;
}

pub fn shouldInitRuntimeExtras() bool {
    return settings().init_runtime_extras;
}

pub fn shouldExitOnCompletion() bool {
    return settings().exit_on_completion;
}

pub fn shouldExitOnPanic() bool {
    return shouldExitOnCompletion();
}
