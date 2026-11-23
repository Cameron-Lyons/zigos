const builtin = @import("builtin");
const std = @import("std");
const build_options = @import("build_options");

pub const BootProfile = @TypeOf(build_options.boot_profile);
pub const KernelRole = @TypeOf(build_options.kernel_role);

/// Boot faults a verification kernel injects to prove fail-closed rejection.
pub const SmokeFault = enum {
    none,
    tampered_artifact_manifest,
    tampered_bootloader_measurement,
    tampered_kernel,
    tampered_userspace_image,
    tampered_policy,
    tampered_driver_set,
    rollback_slot_failure,
    storage_durability,
};

pub fn bootProfile() BootProfile {
    return build_options.boot_profile;
}

/// Whether this boot injects `fault`. Comptime false outside freestanding
/// zigos_native verification kernels, so production, recovery and benchmark
/// kernels and host tests never analyze a fault path. The verification kernel
/// reads at most one `smoke_fault_<name>` flag from its firmware-authenticated
/// command line.
pub inline fn smokeFaultIs(comptime fault: SmokeFault) bool {
    if (builtin.target.os.tag != .freestanding) return false;
    if (comptime kernelRole() != .verification or bootProfile() != .zigos_native) return false;
    return selectedSmokeFault() == fault;
}

fn selectedSmokeFault() SmokeFault {
    const handoff = @import("boot/handoff.zig");
    const info = handoff.capturedInfo() orelse return .none;
    var selected: SmokeFault = .none;
    inline for (comptime std.enums.values(SmokeFault)[1..]) |fault| {
        if (handoff.commandLineHasFlag(info, "smoke_fault_" ++ @tagName(fault))) {
            if (selected != .none) @panic("more than one smoke fault selected");
            selected = fault;
        }
    }
    return selected;
}

pub fn kernelRole() KernelRole {
    return build_options.kernel_role;
}

pub fn includesVerificationEvidence() bool {
    return kernelRole() == .verification;
}

pub fn name() []const u8 {
    return @tagName(build_options.boot_profile);
}

pub fn shouldInitSmp() bool {
    return true;
}

pub fn shouldInitNetworkStack() bool {
    return false;
}

pub fn shouldInitRuntimeExtras() bool {
    return false;
}

pub fn shouldExitOnCompletion() bool {
    return bootProfile() == .benchmark or bootProfile() == .recovery;
}

pub fn shouldExitOnPanic() bool {
    return bootProfile() == .benchmark or bootProfile() == .recovery;
}

pub fn isNativeProfile() bool {
    return bootProfile() == .zigos_native;
}
