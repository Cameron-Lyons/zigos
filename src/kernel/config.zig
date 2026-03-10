const build_options = @import("build_options");

pub const BootProfile = @TypeOf(build_options.boot_profile);

pub fn bootProfile() BootProfile {
    return build_options.boot_profile;
}

pub fn name() []const u8 {
    return switch (bootProfile()) {
        .dev => "dev",
        .ci_smoke => "ci_smoke",
        .test_vm => "test_vm",
        .userland_smoke => "userland_smoke",
        .userland_fs_smoke => "userland_fs_smoke",
    };
}

pub fn shouldInitAcpi() bool {
    return bootProfile() == .dev;
}

pub fn shouldInitSmp() bool {
    return bootProfile() == .dev;
}

pub fn shouldInitNetworkStack() bool {
    return bootProfile() == .dev;
}

pub fn shouldInitRuntimeExtras() bool {
    return bootProfile() == .dev;
}

pub fn shouldExitOnCompletion() bool {
    return bootProfile() != .dev;
}

pub fn shouldExitOnPanic() bool {
    return shouldExitOnCompletion();
}
