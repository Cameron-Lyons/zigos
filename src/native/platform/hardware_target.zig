const std = @import("std");

pub const Subsystem = enum {
    uefi_boot,
    acpi_tables,
    vtd_discovery,
    vtd_storage_isolation,
    vtd_interrupt_isolation,
    vtd_fault_capture,
    apic_timer,
    framebuffer_gop,
    usb_input_xhci,
    nvme_block,
    network_i225_lm,
    compositor_framebuffer,
    suspend_resume,
    crash_recovery,
    crash_persistence,
    update_rollback_power_cycle,
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
    crash_record_persistence_cycles: u16,
    update_rollback_cycles: u16,
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
    crash_record_persistence_cycles: u16 = 0,
    update_rollback_cycles: u16 = 0,
    proof_manifest_captured: bool = false,
    serial_log_captured: bool = false,
    required_markers_captured: bool = false,
    firmware_settings_captured: bool = false,
    power_cycle_notes_captured: bool = false,
    artifact_digests_captured: bool = false,
};

pub const UpdateRollbackEvidenceSource = enum(u8) {
    modeled_selector,
    hardware_power_cycle,
};

pub const HardwareUpdateRollbackEvidence = struct {
    source: UpdateRollbackEvidenceSource = .modeled_selector,
    candidate_activation_writes: u32 = 0,
    selector_record_flushes: u32 = 0,
    power_cycle_observations: u32 = 0,
    failure_detector_observations: u32 = 0,
    rollback_decision_records: u32 = 0,
    stable_slot_boot_observations: u32 = 0,
    recovered_slot_reads: u32 = 0,
    persisted_state_verifications: u32 = 0,
    service_start_suppression_observations: u32 = 0,

    pub fn verified(self: HardwareUpdateRollbackEvidence, proof: UpdateRollbackProof) bool {
        const expected_cycles = @as(u32, proof.cycles);
        return self.source == .hardware_power_cycle and
            expected_cycles > 0 and
            self.candidate_activation_writes >= expected_cycles and
            self.selector_record_flushes >= expected_cycles and
            self.power_cycle_observations >= expected_cycles and
            self.failure_detector_observations >= expected_cycles and
            self.rollback_decision_records >= expected_cycles and
            self.stable_slot_boot_observations >= expected_cycles and
            self.recovered_slot_reads >= expected_cycles and
            self.persisted_state_verifications >= expected_cycles and
            self.service_start_suppression_observations >= expected_cycles;
    }
};

pub const UpdateRollbackProof = struct {
    cycles: u16,
    stable_slot: usize,
    candidate_slot: usize,
    recovered_slot: usize,
    activation_generation_before: u64,
    activation_generation_after: u64,
    rollback_generation_before: u64,
    rollback_generation_after: u64,
    failure_detected: bool,
    rollback_decision: bool,
    service_use_started: bool,
    selector_record_persisted: bool,
    post_power_cycle_verified: bool,
    active_slot_verified: bool,
    persisted_state_preserved: bool,
    hardware_rollback: HardwareUpdateRollbackEvidence = .{},

    pub fn verified(self: UpdateRollbackProof) bool {
        return self.cycles > 0 and
            self.stable_slot != self.candidate_slot and
            self.recovered_slot == self.stable_slot and
            self.activation_generation_after >= self.activation_generation_before and
            self.rollback_generation_after > self.rollback_generation_before and
            self.failure_detected and
            self.rollback_decision and
            !self.service_use_started and
            self.selector_record_persisted and
            self.post_power_cycle_verified and
            self.active_slot_verified and
            self.persisted_state_preserved;
    }

    pub fn productionHardwareVerified(self: UpdateRollbackProof) bool {
        return self.verified() and self.hardware_rollback.verified(self);
    }
};

pub fn withHardwareUpdateRollbackEvidence(
    proof: UpdateRollbackProof,
    evidence: HardwareUpdateRollbackEvidence,
) UpdateRollbackProof {
    var upgraded = proof;
    upgraded.hardware_rollback = evidence;
    return upgraded;
}

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
    .vtd_discovery,
    .vtd_storage_isolation,
    .vtd_interrupt_isolation,
    .vtd_fault_capture,
    .apic_timer,
    .framebuffer_gop,
    .usb_input_xhci,
    .nvme_block,
    .network_i225_lm,
    .compositor_framebuffer,
    .suspend_resume,
    .crash_recovery,
    .crash_persistence,
    .update_rollback_power_cycle,
};

pub const nuc11tnki5_marker_prefix = "ZIGOS:HW_TARGET:INTEL_NUC11TNKI5";

pub const nuc11tnki5_markers = [_][]const u8{
    nuc11tnki5_marker_prefix ++ ":UEFI_BOOT:PASS",
    nuc11tnki5_marker_prefix ++ ":ACPI_TABLES:PASS",
    nuc11tnki5_marker_prefix ++ ":VT_D_DISCOVERY:PASS",
    nuc11tnki5_marker_prefix ++ ":VT_D_STORAGE_ISOLATION:ENFORCED",
    nuc11tnki5_marker_prefix ++ ":VT_D_INTERRUPT_ISOLATION:ENFORCED",
    nuc11tnki5_marker_prefix ++ ":VT_D_BLOCKED_DMA_FAULT:OBSERVED",
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
    nuc11tnki5_marker_prefix ++ ":PROOF_MANIFEST:RECORDED",
    nuc11tnki5_marker_prefix ++ ":FIRMWARE_SETTINGS:RECORDED",
    nuc11tnki5_marker_prefix ++ ":POWER_CYCLE_NOTES:RECORDED",
    nuc11tnki5_marker_prefix ++ ":ARTIFACT_DIGESTS:RECORDED",
};

pub const nuc11tnki5_hardware_fact_markers = [_][]const u8{
    nuc11tnki5_marker_prefix ++ ":SMBIOS_SKU:OBSERVED",
    nuc11tnki5_marker_prefix ++ ":MULTIBOOT_MEMORY_MAP:OBSERVED",
    nuc11tnki5_marker_prefix ++ ":ACPI_XSDT:OBSERVED",
    nuc11tnki5_marker_prefix ++ ":ACPI_MADT:OBSERVED",
    nuc11tnki5_marker_prefix ++ ":ACPI_FADT:OBSERVED",
    nuc11tnki5_marker_prefix ++ ":ACPI_DMAR:OBSERVED",
    nuc11tnki5_marker_prefix ++ ":VT_D_SEGMENT_ZERO:OBSERVED",
    nuc11tnki5_marker_prefix ++ ":APIC_TIMER_INTERRUPT:OBSERVED",
    nuc11tnki5_marker_prefix ++ ":FRAMEBUFFER_GOP_SCANOUT:OBSERVED",
    nuc11tnki5_marker_prefix ++ ":XHCI_BOOT_KEYBOARD_REPORT:OBSERVED",
    nuc11tnki5_marker_prefix ++ ":NVME_WRITE_READ_COMPLETION:OBSERVED",
    nuc11tnki5_marker_prefix ++ ":I225_LM_FRAME_INTERRUPT:OBSERVED",
    nuc11tnki5_marker_prefix ++ ":SUSPEND_RESUME_POWER:OBSERVED",
    nuc11tnki5_marker_prefix ++ ":CRASH_RECORD_REBOOT_PERSISTENCE:OBSERVED",
    nuc11tnki5_marker_prefix ++ ":UPDATE_ROLLBACK_POWER_CYCLE:OBSERVED",
    nuc11tnki5_marker_prefix ++ ":ATTESTATION_ROOT_LIFECYCLE:OBSERVED",
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
        .crash_record_persistence_cycles = 10,
        .update_rollback_cycles = 10,
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
    .{
        .marker_prefix = nuc11tnki5_marker_prefix ++ ":CRASH_RECORD_PERSISTENCE_CYCLES:",
        .minimum = first_supported_target.proof_minimums.crash_record_persistence_cycles,
    },
    .{
        .marker_prefix = nuc11tnki5_marker_prefix ++ ":UPDATE_ROLLBACK_CYCLES:",
        .minimum = first_supported_target.proof_minimums.update_rollback_cycles,
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
        evidence.proof_manifest_captured and
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
        evidence.crash_recovery_cycles >= target.proof_minimums.crash_recovery_cycles and
        evidence.crash_record_persistence_cycles >= target.proof_minimums.crash_record_persistence_cycles and
        evidence.update_rollback_cycles >= target.proof_minimums.update_rollback_cycles;
}
