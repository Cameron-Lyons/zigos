const std = @import("std");

pub const Subsystem = enum {
    uefi_boot,
    acpi_tables,
    apic_timer,
    framebuffer_gop,
    usb_input_xhci,
    nvme_block,
    network_i225_lm,
    suspend_resume,
    crash_recovery,
};

pub const EvidenceSource = enum {
    unknown,
    qemu,
    real_hardware,
};

pub const ProofMinimums = struct {
    cold_boots: u16,
    warm_reboots: u16,
    storage_write_read_cycles: u16,
    network_frame_cycles: u16,
    suspend_resume_cycles: u16,
    crash_recovery_cycles: u16,
};

pub const EvidenceSummary = struct {
    target_id: []const u8,
    source: EvidenceSource = .unknown,
    qemu_boots: u16 = 0,
    hardware_cold_boots: u16 = 0,
    hardware_warm_reboots: u16 = 0,
    storage_write_read_cycles: u16 = 0,
    network_frame_cycles: u16 = 0,
    suspend_resume_cycles: u16 = 0,
    crash_recovery_cycles: u16 = 0,
    serial_log_captured: bool = false,
    required_markers_captured: bool = false,
    firmware_settings_captured: bool = false,
    power_cycle_notes_captured: bool = false,
    artifact_digests_captured: bool = false,
};

pub const Target = struct {
    id: []const u8,
    vendor: []const u8,
    product: []const u8,
    sku: []const u8,
    cpu: []const u8,
    storage: []const u8,
    network: []const u8,
    firmware: []const u8,
    required_subsystems: []const Subsystem,
    required_markers: []const []const u8,
    proof_minimums: ProofMinimums,
};

pub const required_subsystems = [_]Subsystem{
    .uefi_boot,
    .acpi_tables,
    .apic_timer,
    .framebuffer_gop,
    .usb_input_xhci,
    .nvme_block,
    .network_i225_lm,
    .suspend_resume,
    .crash_recovery,
};

pub const nuc11tnki5_marker_prefix = "ZIGOS:HW_TARGET:INTEL_NUC11TNKI5";

pub const nuc11tnki5_markers = [_][]const u8{
    nuc11tnki5_marker_prefix ++ ":UEFI_BOOT:PASS",
    nuc11tnki5_marker_prefix ++ ":ACPI_TABLES:PASS",
    nuc11tnki5_marker_prefix ++ ":APIC_TIMER:PASS",
    nuc11tnki5_marker_prefix ++ ":FRAMEBUFFER_GOP:PASS",
    nuc11tnki5_marker_prefix ++ ":USB_INPUT_XHCI:PASS",
    nuc11tnki5_marker_prefix ++ ":NVME_BLOCK:PASS",
    nuc11tnki5_marker_prefix ++ ":NETWORK_I225_LM:PASS",
    nuc11tnki5_marker_prefix ++ ":SUSPEND_RESUME:PASS",
    nuc11tnki5_marker_prefix ++ ":CRASH_RECOVERY:PASS",
};

pub const nuc11tnki5_proof_metadata_markers = [_][]const u8{
    nuc11tnki5_marker_prefix ++ ":EVIDENCE_SOURCE:REAL_HARDWARE",
    nuc11tnki5_marker_prefix ++ ":BOARD_SKU:NUC11TNKi5",
    nuc11tnki5_marker_prefix ++ ":FIRMWARE_SETTINGS:RECORDED",
    nuc11tnki5_marker_prefix ++ ":POWER_CYCLE_NOTES:RECORDED",
    nuc11tnki5_marker_prefix ++ ":ARTIFACT_DIGESTS:RECORDED",
};

pub const first_supported_target = Target{
    .id = "intel-nuc11tnki5",
    .vendor = "Intel",
    .product = "NUC 11 Pro Kit",
    .sku = "NUC11TNKi5",
    .cpu = "Core i5-1135G7 Tiger Lake",
    .storage = "M.2 2280 PCIe NVMe SSD",
    .network = "Intel Ethernet Controller I225-LM",
    .firmware = "UEFI firmware with ACPI wake support",
    .required_subsystems = &required_subsystems,
    .required_markers = &nuc11tnki5_markers,
    .proof_minimums = .{
        .cold_boots = 10,
        .warm_reboots = 10,
        .storage_write_read_cycles = 100,
        .network_frame_cycles = 100,
        .suspend_resume_cycles = 20,
        .crash_recovery_cycles = 10,
    },
};

pub const CounterMarker = struct {
    marker_prefix: []const u8,
    minimum: u16,
};

pub const nuc11tnki5_counter_markers = [_]CounterMarker{
    .{
        .marker_prefix = nuc11tnki5_marker_prefix ++ ":COLD_BOOTS:",
        .minimum = first_supported_target.proof_minimums.cold_boots,
    },
    .{
        .marker_prefix = nuc11tnki5_marker_prefix ++ ":WARM_REBOOTS:",
        .minimum = first_supported_target.proof_minimums.warm_reboots,
    },
    .{
        .marker_prefix = nuc11tnki5_marker_prefix ++ ":STORAGE_WRITE_READ_CYCLES:",
        .minimum = first_supported_target.proof_minimums.storage_write_read_cycles,
    },
    .{
        .marker_prefix = nuc11tnki5_marker_prefix ++ ":NETWORK_FRAME_CYCLES:",
        .minimum = first_supported_target.proof_minimums.network_frame_cycles,
    },
    .{
        .marker_prefix = nuc11tnki5_marker_prefix ++ ":SUSPEND_RESUME_CYCLES:",
        .minimum = first_supported_target.proof_minimums.suspend_resume_cycles,
    },
    .{
        .marker_prefix = nuc11tnki5_marker_prefix ++ ":CRASH_RECOVERY_CYCLES:",
        .minimum = first_supported_target.proof_minimums.crash_recovery_cycles,
    },
};

pub fn coversSubsystem(target: *const Target, subsystem: Subsystem) bool {
    for (target.required_subsystems) |candidate| {
        if (candidate == subsystem) return true;
    }
    return false;
}

pub fn coversRequiredSubsystems(target: *const Target) bool {
    for (required_subsystems) |subsystem| {
        if (!coversSubsystem(target, subsystem)) return false;
    }
    return true;
}

pub fn hardwareProofSatisfied(target: *const Target, evidence: EvidenceSummary) bool {
    return std.mem.eql(u8, evidence.target_id, target.id) and
        evidence.source == .real_hardware and
        evidence.serial_log_captured and
        evidence.required_markers_captured and
        evidence.firmware_settings_captured and
        evidence.power_cycle_notes_captured and
        evidence.artifact_digests_captured and
        evidence.hardware_cold_boots >= target.proof_minimums.cold_boots and
        evidence.hardware_warm_reboots >= target.proof_minimums.warm_reboots and
        evidence.storage_write_read_cycles >= target.proof_minimums.storage_write_read_cycles and
        evidence.network_frame_cycles >= target.proof_minimums.network_frame_cycles and
        evidence.suspend_resume_cycles >= target.proof_minimums.suspend_resume_cycles and
        evidence.crash_recovery_cycles >= target.proof_minimums.crash_recovery_cycles;
}
