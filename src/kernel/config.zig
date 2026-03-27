const build_options = @import("build_options");

pub const BootProfile = @TypeOf(build_options.boot_profile);

pub fn bootProfile() BootProfile {
    return build_options.boot_profile;
}

pub fn name() []const u8 {
    return "zigos_native";
}

pub fn shouldInitAcpi() bool {
    return false;
}

pub fn shouldInitSmp() bool {
    return false;
}

pub fn shouldInitNetworkStack() bool {
    return false;
}

pub fn shouldInitRuntimeExtras() bool {
    return false;
}

pub fn shouldExitOnCompletion() bool {
    return false;
}

pub fn shouldExitOnPanic() bool {
    return false;
}

pub fn isNativeProfile() bool {
    return true;
}
