const std = @import("std");
const builtin = @import("builtin");
const acpi = @import("acpi.zig");
const apic = @import("apic.zig");
const dmar = @import("dmar.zig");
const fadt = @import("fadt.zig");
const mcfg = @import("mcfg.zig");
const framebuffer = @import("framebuffer.zig");
const smbios = @import("smbios.zig");
const crash_record = @import("crash_record.zig");
const handoff = @import("../boot/handoff.zig");
const console = @import("../utils/console.zig");
const paging = @import("../memory/paging64.zig");
const intel_i225 = @import("../drivers/intel_i225.zig");
const intel_vtd = @import("intel_vtd.zig");
const nvme = @import("../drivers/nvme.zig");
const pci = @import("../drivers/pci.zig");
const xhci = @import("../drivers/xhci.zig");
const hardware_target = @import("../../native/platform/hardware_target.zig");

const MAX_ACPI_TABLE_BYTES: usize = 1024 * 1024;
const PAGE_SIZE: usize = 4096;
const PAGE_MASK: usize = PAGE_SIZE - 1;
const MAX_X86_PHYSICAL_ADDRESS: u64 = 0x000F_FFFF_FFFF_FFFF;
const KERNEL_ACPI_ROOT_VIRTUAL_BASE: usize = 0xFFFF_8000_2000_0000;
const KERNEL_ACPI_ENTRY_VIRTUAL_BASE: usize = 0xFFFF_8000_2020_0000;

pub const ProbeFacts = struct {
    real_target_sku: bool = false,
    multiboot_handoff: bool = false,
    memory_map: bool = false,
    memory_capacity_bytes: usize = 0,
    acpi_xsdt: bool = false,
    acpi_madt: bool = false,
    acpi_fadt: bool = false,
    acpi_mcfg: bool = false,
    acpi_dmar: bool = false,
    fadt_firmware: ?fadt.FixedAcpiDescription = null,
    mcfg_allocation: ?mcfg.Allocation = null,
    dmar_summary: ?dmar.Summary = null,
    vtd_storage_isolation: bool = false,
    vtd_interrupt_isolation: bool = false,
    vtd_blocked_dma_fault: bool = false,
    apic_timer: bool = false,
    framebuffer_gop: bool = false,
    xhci_controller: bool = false,
    xhci_keyboard_input: bool = false,
    nvme_controller: bool = false,
    nvme_write_read_io: bool = false,
    i225_lm_controller: bool = false,
    i225_frame_io: bool = false,
    cold_boots: u16 = 0,
    warm_reboots: u16 = 0,
    storage_write_read_cycles: u16 = 0,
    network_frame_cycles: u16 = 0,
    suspend_resume_power: bool = false,
    suspend_resume_cycles: u16 = 0,
    crash_recovery_record: bool = false,
    crash_recovery_cycles: u16 = 0,
    crash_record_persisted: bool = false,
    crash_record_persistence_cycles: u16 = 0,
    update_rollback_power_cycle: bool = false,
    update_rollback_cycles: u16 = 0,
    telemetry_reader_generation: u32 = 0,
    thermal_zone_count: u16 = 0,
    thermal_sample_sequence: u64 = 0,
    thermal_milli_celsius: u32 = 0,
    battery_device_count: u16 = 0,
    battery_sample_sequence: u64 = 0,
    battery_percent: u8 = 0,
    battery_charging: bool = false,
    gpu_driver_online: bool = false,
    npu_driver_online: bool = false,
    media_driver_online: bool = false,
    gpu_driver_generation: u32 = 0,
    npu_driver_generation: u32 = 0,
    media_driver_generation: u32 = 0,
    accelerator_sample_sequence: u64 = 0,
    accelerator_completion_interrupts: u32 = 0,
    grid_carbon_intensity_observed: bool = false,
    grid_carbon_sample_sequence: u64 = 0,
    grid_carbon_intensity_grams_per_kwh: u16 = 0,
    attestation_root_lifecycle_observed: bool = false,
    attestation_root_initial_generation: u64 = 0,
    attestation_root_active_generation: u64 = 0,
    attestation_root_revoked_generation_count: u8 = 0,
    attestation_root_stale_generation_rejected: bool = false,
    attestation_root_revoked_generation_rejected: bool = false,
    attestation_stale_attestation_rejected_by_verifier: bool = false,
    attestation_verifier_metadata_digest_bound: bool = false,

    pub fn uefiBootReady(self: ProbeFacts) bool {
        return self.real_target_sku and self.multiboot_handoff and self.memory_map and self.framebuffer_gop;
    }

    pub fn acpiTablesReady(self: ProbeFacts) bool {
        return self.acpi_xsdt and self.acpi_madt and self.acpi_fadt and self.acpi_mcfg and self.acpi_dmar;
    }

    pub fn vtdDiscoveryReady(self: ProbeFacts) bool {
        if (!self.real_target_sku or !self.acpi_dmar) return false;
        const summary = self.dmar_summary orelse return false;
        return summary.productionDiscoveryReady();
    }

    pub fn vtdStorageIsolationReady(self: ProbeFacts) bool {
        return self.vtdDiscoveryReady() and self.vtd_storage_isolation;
    }

    pub fn vtdInterruptIsolationReady(self: ProbeFacts) bool {
        return self.vtdStorageIsolationReady() and self.vtd_interrupt_isolation;
    }

    pub fn vtdFaultProofReady(self: ProbeFacts) bool {
        return self.vtdInterruptIsolationReady() and self.vtd_blocked_dma_fault;
    }

    pub fn nvmeBlockReady(self: ProbeFacts) bool {
        return self.nvme_controller and
            self.nvme_write_read_io and
            self.storage_write_read_cycles >= hardware_target.first_supported_target.proof_minimums.storage_write_read_cycles;
    }

    pub fn i225PacketIoReady(self: ProbeFacts) bool {
        return self.i225_lm_controller and
            self.i225_frame_io and
            self.network_frame_cycles >= hardware_target.first_supported_target.proof_minimums.network_frame_cycles;
    }

    pub fn suspendResumeReady(self: ProbeFacts) bool {
        return self.suspend_resume_power and
            self.suspend_resume_cycles >= hardware_target.first_supported_target.proof_minimums.suspend_resume_cycles;
    }

    pub fn crashRecoveryReady(self: ProbeFacts) bool {
        return self.crash_recovery_record and
            self.crash_recovery_cycles >= hardware_target.first_supported_target.proof_minimums.crash_recovery_cycles;
    }

    pub fn crashRecordPersistenceReady(self: ProbeFacts) bool {
        return self.crash_record_persisted and
            self.crash_record_persistence_cycles >= hardware_target.first_supported_target.proof_minimums.crash_record_persistence_cycles;
    }

    pub fn updateRollbackReady(self: ProbeFacts) bool {
        return self.update_rollback_power_cycle and
            self.update_rollback_cycles >= hardware_target.first_supported_target.proof_minimums.update_rollback_cycles;
    }

    pub fn acpiTelemetryFacts(self: ProbeFacts) ?AcpiTelemetryFacts {
        if (!self.real_target_sku or !self.acpi_fadt) return null;
        const firmware = self.fadt_firmware orelse return null;
        if (self.thermal_zone_count == 0 or self.battery_device_count == 0) return null;
        return .{
            .firmware = firmware,
            .thermal_zone_count = self.thermal_zone_count,
            .battery_device_count = self.battery_device_count,
        };
    }

    pub fn thermalTelemetryFacts(self: ProbeFacts) ?ThermalTelemetryFacts {
        if (self.telemetry_reader_generation == 0 or self.thermal_zone_count == 0 or self.thermal_sample_sequence == 0) return null;
        if (self.thermal_milli_celsius > MAX_TELEMETRY_THERMAL_MILLI_CELSIUS) return null;
        return .{
            .zone_count = self.thermal_zone_count,
            .sample_sequence = self.thermal_sample_sequence,
            .thermal_milli_celsius = self.thermal_milli_celsius,
        };
    }

    pub fn batteryTelemetryFacts(self: ProbeFacts) ?BatteryTelemetryFacts {
        if (self.telemetry_reader_generation == 0 or self.battery_device_count == 0 or self.battery_sample_sequence == 0) return null;
        if (self.battery_percent > 100) return null;
        return .{
            .battery_device_count = self.battery_device_count,
            .sample_sequence = self.battery_sample_sequence,
            .battery_percent = self.battery_percent,
            .charging = self.battery_charging,
        };
    }

    pub fn acceleratorTelemetryFacts(self: ProbeFacts) ?AcceleratorTelemetryFacts {
        if (self.telemetry_reader_generation == 0 or self.accelerator_sample_sequence == 0 or self.accelerator_completion_interrupts == 0) return null;
        if (!acceleratorDriverStateVerified(self.gpu_driver_online, self.gpu_driver_generation)) return null;
        if (!acceleratorDriverStateVerified(self.npu_driver_online, self.npu_driver_generation)) return null;
        if (!acceleratorDriverStateVerified(self.media_driver_online, self.media_driver_generation)) return null;
        return .{
            .sample_sequence = self.accelerator_sample_sequence,
            .gpu_driver_online = self.gpu_driver_online,
            .npu_driver_online = self.npu_driver_online,
            .media_driver_online = self.media_driver_online,
            .gpu_driver_generation = self.gpu_driver_generation,
            .npu_driver_generation = self.npu_driver_generation,
            .media_driver_generation = self.media_driver_generation,
            .completion_interrupts_observed = self.accelerator_completion_interrupts,
        };
    }

    pub fn gridCarbonTelemetryFacts(self: ProbeFacts) ?GridCarbonTelemetryFacts {
        if (self.telemetry_reader_generation == 0 or !self.grid_carbon_intensity_observed or self.grid_carbon_sample_sequence == 0) return null;
        if (self.grid_carbon_intensity_grams_per_kwh > MAX_GRID_CARBON_INTENSITY_GRAMS_PER_KWH) return null;
        return .{
            .sample_sequence = self.grid_carbon_sample_sequence,
            .grams_per_kwh = self.grid_carbon_intensity_grams_per_kwh,
        };
    }

    pub fn attestationRootLifecycleFacts(self: ProbeFacts) ?AttestationRootLifecycleFacts {
        if (!self.attestation_root_lifecycle_observed) return null;
        if (self.attestation_root_initial_generation == 0) return null;
        if (self.attestation_root_active_generation <= self.attestation_root_initial_generation) return null;
        if (self.attestation_root_revoked_generation_count == 0) return null;
        if (!self.attestation_root_stale_generation_rejected) return null;
        if (!self.attestation_root_revoked_generation_rejected) return null;
        if (!self.attestation_stale_attestation_rejected_by_verifier) return null;
        if (!self.attestation_verifier_metadata_digest_bound) return null;
        return .{
            .initial_generation = self.attestation_root_initial_generation,
            .active_generation = self.attestation_root_active_generation,
            .revoked_generation_count = self.attestation_root_revoked_generation_count,
            .stale_generation_rejected = self.attestation_root_stale_generation_rejected,
            .revoked_generation_rejected = self.attestation_root_revoked_generation_rejected,
            .verifier_rejected_stale_attestation = self.attestation_stale_attestation_rejected_by_verifier,
            .verifier_metadata_digest_bound = self.attestation_verifier_metadata_digest_bound,
        };
    }
};

const MAX_TELEMETRY_THERMAL_MILLI_CELSIUS: u32 = 125_000;
pub const MAX_GRID_CARBON_INTENSITY_GRAMS_PER_KWH: u16 = 2_000;

pub const AcpiTelemetryFacts = struct {
    firmware: fadt.FixedAcpiDescription,
    thermal_zone_count: u16,
    battery_device_count: u16,
};

pub const TelemetryBaseProof = struct {
    target_id: []const u8 = hardware_target.first_supported_target.id,
    source: hardware_target.EvidenceSource = .unknown,
    firmware: fadt.FixedAcpiDescription,
    memory_capacity_bytes: usize = 0,

    pub fn verified(self: TelemetryBaseProof) bool {
        return std.mem.eql(u8, self.target_id, hardware_target.first_supported_target.id) and
            self.source == .real_hardware and
            self.memory_capacity_bytes != 0 and
            firmwareSupportsTelemetry(self.firmware);
    }
};

pub const ThermalZoneSample = struct {
    reader_generation: u32,
    zone_count: u16,
    sample_sequence: u64,
    thermal_milli_celsius: u32,

    pub fn verified(self: ThermalZoneSample) bool {
        return self.reader_generation != 0 and
            self.zone_count != 0 and
            self.sample_sequence != 0 and
            self.thermal_milli_celsius <= MAX_TELEMETRY_THERMAL_MILLI_CELSIUS;
    }
};

pub const ThermalTelemetryFacts = struct {
    zone_count: u16,
    sample_sequence: u64,
    thermal_milli_celsius: u32,
};

pub const BatteryStatusSample = struct {
    reader_generation: u32,
    battery_device_count: u16,
    sample_sequence: u64,
    battery_percent: u8,
    charging: bool,

    pub fn verified(self: BatteryStatusSample) bool {
        return self.reader_generation != 0 and
            self.battery_device_count != 0 and
            self.sample_sequence != 0 and
            self.battery_percent <= 100;
    }
};

pub const BatteryTelemetryFacts = struct {
    battery_device_count: u16,
    sample_sequence: u64,
    battery_percent: u8,
    charging: bool,
};

pub const AcceleratorDriverSample = struct {
    reader_generation: u32,
    sample_sequence: u64,
    gpu_driver_online: bool = false,
    npu_driver_online: bool = false,
    media_driver_online: bool = false,
    gpu_driver_generation: u32 = 0,
    npu_driver_generation: u32 = 0,
    media_driver_generation: u32 = 0,
    completion_interrupts_observed: u32 = 0,

    pub fn verified(self: AcceleratorDriverSample) bool {
        return self.reader_generation != 0 and
            self.sample_sequence != 0 and
            self.completion_interrupts_observed != 0 and
            acceleratorDriverStateVerified(self.gpu_driver_online, self.gpu_driver_generation) and
            acceleratorDriverStateVerified(self.npu_driver_online, self.npu_driver_generation) and
            acceleratorDriverStateVerified(self.media_driver_online, self.media_driver_generation);
    }
};

pub const AcceleratorTelemetryFacts = struct {
    sample_sequence: u64,
    gpu_driver_online: bool,
    npu_driver_online: bool,
    media_driver_online: bool,
    gpu_driver_generation: u32,
    npu_driver_generation: u32,
    media_driver_generation: u32,
    completion_interrupts_observed: u32,
};

pub const GridCarbonIntensitySample = struct {
    reader_generation: u32,
    sample_sequence: u64,
    grams_per_kwh: u16,

    pub fn verified(self: GridCarbonIntensitySample) bool {
        return self.reader_generation != 0 and
            self.sample_sequence != 0 and
            self.grams_per_kwh <= MAX_GRID_CARBON_INTENSITY_GRAMS_PER_KWH;
    }
};

pub const GridCarbonTelemetryFacts = struct {
    sample_sequence: u64,
    grams_per_kwh: u16,
};

pub const AttestationRootLifecycleProof = struct {
    target_id: []const u8 = hardware_target.first_supported_target.id,
    source: hardware_target.EvidenceSource = .unknown,
    initial_generation: u64 = 0,
    active_generation: u64 = 0,
    revoked_generation_count: u8 = 0,
    stale_generation_rejected: bool = false,
    revoked_generation_rejected: bool = false,
    verifier_rejected_stale_attestation: bool = false,
    verifier_metadata_digest_bound: bool = false,

    pub fn verified(self: AttestationRootLifecycleProof) bool {
        return std.mem.eql(u8, self.target_id, hardware_target.first_supported_target.id) and
            self.source == .real_hardware and
            self.initial_generation != 0 and
            self.active_generation > self.initial_generation and
            self.revoked_generation_count != 0 and
            self.stale_generation_rejected and
            self.revoked_generation_rejected and
            self.verifier_rejected_stale_attestation and
            self.verifier_metadata_digest_bound;
    }
};

pub const AttestationRootLifecycleFacts = struct {
    initial_generation: u64,
    active_generation: u64,
    revoked_generation_count: u8,
    stale_generation_rejected: bool,
    revoked_generation_rejected: bool,
    verifier_rejected_stale_attestation: bool,
    verifier_metadata_digest_bound: bool,
};

const PrintedMarkers = struct {
    source: bool = false,
    board: bool = false,
    smbios_sku: bool = false,
    multiboot_memory_map: bool = false,
    acpi_xsdt: bool = false,
    acpi_madt: bool = false,
    acpi_fadt: bool = false,
    acpi_dmar: bool = false,
    vtd_segment_zero: bool = false,
    apic_timer_interrupt: bool = false,
    framebuffer_scanout: bool = false,
    xhci_keyboard_report: bool = false,
    nvme_write_read_completion: bool = false,
    i225_frame_interrupt: bool = false,
    suspend_resume_power: bool = false,
    crash_record_reboot_persistence: bool = false,
    update_rollback_power_cycle: bool = false,
    attestation_root_lifecycle: bool = false,
    uefi: bool = false,
    acpi_tables: bool = false,
    vtd_discovery: bool = false,
    vtd_storage_isolation: bool = false,
    vtd_interrupt_isolation: bool = false,
    vtd_blocked_dma_fault: bool = false,
    apic_timer: bool = false,
    framebuffer_gop: bool = false,
    xhci_input: bool = false,
    nvme_block: bool = false,
    i225_packet_io: bool = false,
    suspend_resume: bool = false,
    crash_recovery: bool = false,
    cold_boots: bool = false,
    warm_reboots: bool = false,
    storage_cycles: bool = false,
    network_cycles: bool = false,
    suspend_cycles: bool = false,
    crash_cycles: bool = false,
    crash_record_persistence_cycles: bool = false,
    update_rollback_cycles: bool = false,
};

var facts = ProbeFacts{};
var printed = PrintedMarkers{};

pub fn resetForTest() void {
    facts = .{};
    printed = .{};
}

pub fn factsForTest() ProbeFacts {
    return factsSnapshot();
}

pub fn factsSnapshot() ProbeFacts {
    return facts;
}

pub fn pciEcamAllocation() ?mcfg.Allocation {
    if (!facts.acpi_mcfg) return null;
    return facts.mcfg_allocation;
}

pub fn vtdSummary() ?dmar.Summary {
    if (!facts.vtdDiscoveryReady()) return null;
    return facts.dmar_summary;
}

pub fn realTargetDetected() bool {
    return facts.real_target_sku;
}

pub fn telemetryRecordingReady() bool {
    return facts.real_target_sku and
        facts.acpi_fadt and
        facts.fadt_firmware != null and
        facts.memory_capacity_bytes != 0;
}

pub fn evaluateEvidence(probe: ProbeFacts) hardware_target.EvidenceSummary {
    return .{
        .target_id = hardware_target.first_supported_target.id,
        .source = if (probe.real_target_sku) .real_hardware else .unknown,
        .hardware_cold_boots = probe.cold_boots,
        .hardware_warm_reboots = probe.warm_reboots,
        .storage_write_read_cycles = probe.storage_write_read_cycles,
        .network_frame_cycles = probe.network_frame_cycles,
        .suspend_resume_cycles = probe.suspend_resume_cycles,
        .crash_recovery_cycles = probe.crash_recovery_cycles,
        .crash_record_persistence_cycles = probe.crash_record_persistence_cycles,
        .update_rollback_cycles = probe.update_rollback_cycles,
        .required_markers_captured = allSubsystemMarkersReady(probe),
    };
}

pub fn allSubsystemMarkersReady(probe: ProbeFacts) bool {
    return probe.uefiBootReady() and
        probe.acpiTablesReady() and
        probe.vtdDiscoveryReady() and
        probe.vtdStorageIsolationReady() and
        probe.vtdInterruptIsolationReady() and
        probe.vtdFaultProofReady() and
        probe.apic_timer and
        probe.framebuffer_gop and
        probe.xhci_keyboard_input and
        probe.nvmeBlockReady() and
        probe.i225PacketIoReady() and
        probe.suspendResumeReady() and
        probe.crashRecoveryReady() and
        probe.crashRecordPersistenceReady() and
        probe.updateRollbackReady();
}

pub fn countersReady(probe: ProbeFacts) bool {
    const minimums = hardware_target.first_supported_target.proof_minimums;
    return probe.cold_boots >= minimums.cold_boots and
        probe.warm_reboots >= minimums.warm_reboots and
        probe.storage_write_read_cycles >= minimums.storage_write_read_cycles and
        probe.network_frame_cycles >= minimums.network_frame_cycles and
        probe.suspend_resume_cycles >= minimums.suspend_resume_cycles and
        probe.crash_recovery_cycles >= minimums.crash_recovery_cycles and
        probe.crash_record_persistence_cycles >= minimums.crash_record_persistence_cycles and
        probe.update_rollback_cycles >= minimums.update_rollback_cycles;
}

pub fn captureEarlyBootEvidence() void {
    facts.real_target_sku = smbios.scanBiosForNuc11Tnki5();

    if (handoff.capturedInfo()) |info| {
        facts.multiboot_handoff = true;
        if (handoff.capturedMemoryMapSummary(info)) |summary| {
            facts.memory_map = summary.hasUsableMemory();
            if (summary.hasUsableMemory()) {
                const max_usable: u64 = std.math.maxInt(usize);
                const bounded_usable = @min(summary.usable_bytes, max_usable);
                facts.memory_capacity_bytes = @intCast(bounded_usable);
            }
        }
        _ = handoff.framebufferInfo(info) catch {};
    }

    printNewMarkers();
}

pub fn capturePlatformFirmwareEvidence() void {
    captureAcpiEvidence();
    printNewMarkers();
}

pub fn capturePciEvidence() void {
    facts.nvme_controller = pci.firstNvmeController() != null;
    facts.i225_lm_controller = pci.firstIntelI225Lm() != null;
    facts.xhci_controller = pci.firstXhciController() != null;
    printNewMarkers();
}

pub fn recordVtdIsolationProof(proof: intel_vtd.FaultRecord) void {
    if (facts.real_target_sku and facts.vtdDiscoveryReady() and
        intel_vtd.dmaIsolationEnabled() and
        intel_vtd.interruptIsolationEnabled() and
        intel_vtd.faultMonitoringEnabled())
    {
        facts.vtd_storage_isolation = true;
        facts.vtd_interrupt_isolation = true;
        facts.vtd_blocked_dma_fault = if (intel_vtd.blockedDmaProof()) |captured|
            std.meta.eql(captured, proof) and proof.reason < 0x20 and proof.request_type == .write
        else
            false;
    }
    printNewMarkers();
}

pub fn recordInputProof(proof: xhci.InputProof) void {
    facts.xhci_keyboard_input = facts.xhci_controller and proof.productionHardwareVerified();
    printNewMarkers();
}

pub fn recordStorageProof(proof: nvme.IoProof) void {
    if (facts.nvme_controller and proof.productionHardwareVerified()) {
        facts.nvme_write_read_io = true;
        facts.storage_write_read_cycles = @max(facts.storage_write_read_cycles, proof.write_read_cycles);
    }
    printNewMarkers();
}

pub fn recordNetworkProof(proof: intel_i225.PacketProof) void {
    if (facts.i225_lm_controller and proof.productionHardwareVerified()) {
        facts.i225_frame_io = true;
        facts.network_frame_cycles = @max(facts.network_frame_cycles, proof.tx_rx_cycles);
    }
    printNewMarkers();
}

pub fn recordApicTimerProof(proof: apic.TimerInterruptProof) void {
    if (facts.acpi_madt and proof.productionHardwareVerified()) {
        facts.apic_timer = true;
    }
    printNewMarkers();
}

pub fn recordFramebufferProof(proof: framebuffer.ScanoutProof) void {
    if (facts.multiboot_handoff and proof.productionHardwareVerified()) {
        facts.framebuffer_gop = true;
    }
    printNewMarkers();
}

pub fn recordPowerCycleCounts(cold_boots: u16, warm_reboots: u16) void {
    facts.cold_boots = @max(facts.cold_boots, cold_boots);
    facts.warm_reboots = @max(facts.warm_reboots, warm_reboots);
    printNewMarkers();
}

pub fn recordSuspendResumeProof(proof: fadt.SuspendResumeProof) void {
    if (facts.acpi_fadt and proof.productionHardwareVerified()) {
        facts.suspend_resume_power = true;
        facts.suspend_resume_cycles = @max(facts.suspend_resume_cycles, proof.cycles);
    }
    printNewMarkers();
}

pub fn recordCrashPersistenceProof(proof: crash_record.PersistenceProof) void {
    if (proof.productionHardwareVerified()) {
        facts.crash_recovery_record = true;
        facts.crash_record_persisted = true;
        facts.crash_recovery_cycles = @max(facts.crash_recovery_cycles, proof.cycles);
        facts.crash_record_persistence_cycles = @max(facts.crash_record_persistence_cycles, proof.cycles);
    }
    printNewMarkers();
}

pub fn recordUpdateRollbackProof(proof: hardware_target.UpdateRollbackProof) void {
    if (proof.productionHardwareVerified()) {
        facts.update_rollback_power_cycle = true;
        facts.update_rollback_cycles = @max(facts.update_rollback_cycles, proof.cycles);
    }
    printNewMarkers();
}

pub fn recordAttestationRootLifecycleProof(proof: AttestationRootLifecycleProof) bool {
    if (!proof.verified()) return false;
    facts.real_target_sku = true;
    facts.attestation_root_lifecycle_observed = true;
    facts.attestation_root_initial_generation = proof.initial_generation;
    facts.attestation_root_active_generation = proof.active_generation;
    facts.attestation_root_revoked_generation_count = proof.revoked_generation_count;
    facts.attestation_root_stale_generation_rejected = proof.stale_generation_rejected;
    facts.attestation_root_revoked_generation_rejected = proof.revoked_generation_rejected;
    facts.attestation_stale_attestation_rejected_by_verifier = proof.verifier_rejected_stale_attestation;
    facts.attestation_verifier_metadata_digest_bound = proof.verifier_metadata_digest_bound;
    printNewMarkers();
    return true;
}

pub fn recordTelemetryBaseProof(proof: TelemetryBaseProof) bool {
    if (!proof.verified()) return false;
    facts.real_target_sku = true;
    facts.acpi_fadt = true;
    facts.fadt_firmware = proof.firmware;
    facts.memory_capacity_bytes = proof.memory_capacity_bytes;
    return true;
}

pub fn recordThermalZoneSample(sample: ThermalZoneSample) void {
    if (facts.real_target_sku and facts.acpi_fadt and sample.verified() and acceptTelemetryGeneration(sample.reader_generation)) {
        facts.thermal_zone_count = sample.zone_count;
        facts.thermal_sample_sequence = sample.sample_sequence;
        facts.thermal_milli_celsius = sample.thermal_milli_celsius;
    }
}

pub fn recordBatteryStatusSample(sample: BatteryStatusSample) void {
    if (facts.real_target_sku and facts.acpi_fadt and sample.verified() and acceptTelemetryGeneration(sample.reader_generation)) {
        facts.battery_device_count = sample.battery_device_count;
        facts.battery_sample_sequence = sample.sample_sequence;
        facts.battery_percent = sample.battery_percent;
        facts.battery_charging = sample.charging;
    }
}

pub fn recordAcceleratorDriverSample(sample: AcceleratorDriverSample) void {
    if (facts.real_target_sku and sample.verified() and acceptTelemetryGeneration(sample.reader_generation)) {
        facts.gpu_driver_online = sample.gpu_driver_online;
        facts.npu_driver_online = sample.npu_driver_online;
        facts.media_driver_online = sample.media_driver_online;
        facts.gpu_driver_generation = sample.gpu_driver_generation;
        facts.npu_driver_generation = sample.npu_driver_generation;
        facts.media_driver_generation = sample.media_driver_generation;
        facts.accelerator_sample_sequence = sample.sample_sequence;
        facts.accelerator_completion_interrupts = sample.completion_interrupts_observed;
    }
}

pub fn recordGridCarbonIntensitySample(sample: GridCarbonIntensitySample) void {
    if (facts.real_target_sku and sample.verified() and acceptTelemetryGeneration(sample.reader_generation)) {
        facts.grid_carbon_intensity_observed = true;
        facts.grid_carbon_sample_sequence = sample.sample_sequence;
        facts.grid_carbon_intensity_grams_per_kwh = sample.grams_per_kwh;
    }
}

fn captureAcpiEvidence() void {
    const rsdp = capturedRsdp() orelse return;
    const xsdt = mappedPhysicalTableBytes(rsdp.xsdt_address, KERNEL_ACPI_ROOT_VIRTUAL_BASE) orelse return;
    const count = acpi.xsdtEntryCount(xsdt) catch return;
    facts.acpi_xsdt = true;
    var found_madt = false;
    var found_fadt = false;
    var found_mcfg: ?mcfg.Allocation = null;
    var found_dmar: ?dmar.Summary = null;
    var dmar_table_seen = false;
    var index: u32 = 0;
    while (index < count) : (index += 1) {
        const table_address = acpi.xsdtEntryAddress(xsdt, index) catch continue;
        const table = mappedPhysicalTableBytes(table_address, KERNEL_ACPI_ENTRY_VIRTUAL_BASE) orelse continue;
        const header = acpi.parseSdtHeader(table) catch continue;
        if (std.mem.eql(u8, header.signature[0..], apic.MADT_SIGNATURE)) {
            if (apic.parseMadt(table)) |summary| {
                found_madt = summary.local_apic_address != 0 and summary.enabled_processor_count > 0;
            } else |_| {}
        } else if (std.mem.eql(u8, header.signature[0..], fadt.FADT_SIGNATURE)) {
            const firmware = fadt.parseFadt(table) catch continue;
            facts.fadt_firmware = firmware;
            found_fadt = true;
        } else if (std.mem.eql(u8, header.signature[0..], mcfg.MCFG_SIGNATURE)) {
            found_mcfg = mcfg.segmentZeroAllocation(table) catch continue;
        } else if (std.mem.eql(u8, header.signature[0..], dmar.DMAR_SIGNATURE)) {
            if (dmar_table_seen) {
                found_dmar = null;
                continue;
            }
            dmar_table_seen = true;
            found_dmar = dmar.parseDmar(table) catch continue;
        }
    }

    facts.acpi_madt = found_madt;
    facts.acpi_fadt = found_fadt;
    facts.acpi_mcfg = found_mcfg != null;
    facts.mcfg_allocation = found_mcfg;
    facts.acpi_dmar = found_dmar != null;
    facts.dmar_summary = found_dmar;
}

fn acceptTelemetryGeneration(reader_generation: u32) bool {
    if (reader_generation == 0) return false;
    if (facts.telemetry_reader_generation == 0) {
        facts.telemetry_reader_generation = reader_generation;
        return true;
    }
    return facts.telemetry_reader_generation == reader_generation;
}

fn acceleratorDriverStateVerified(online: bool, generation: u32) bool {
    return !online or generation != 0;
}

fn firmwareSupportsTelemetry(firmware: fadt.FixedAcpiDescription) bool {
    return firmware.sci_interrupt != 0 and
        (firmware.pm1a_event_block != 0 or firmware.pm1b_event_block != 0) and
        (firmware.pm1a_control_block != 0 or firmware.pm1b_control_block != 0) and
        firmware.pm1_control_length >= 2 and
        firmware.pm_timer_block != 0 and
        firmware.pm_timer_length != 0;
}

fn capturedRsdp() ?acpi.Rsdp {
    const info = handoff.capturedInfo() orelse return null;
    const bytes = handoff.capturedAcpi2Rsdp(info) orelse return null;
    return acpi.parseRsdp(bytes) catch null;
}

fn mappedPhysicalTableBytes(physical_address: u64, virtual_base: usize) ?[]const u8 {
    if (physical_address == 0 or physical_address > MAX_X86_PHYSICAL_ADDRESS - acpi.SDT_HEADER_LENGTH) return null;
    const address = std.math.cast(usize, physical_address) orelse return null;
    const physical_page = address & ~PAGE_MASK;
    const page_offset = address & PAGE_MASK;
    const header_span = std.math.add(usize, page_offset, acpi.SDT_HEADER_LENGTH) catch return null;
    const header_pages = (header_span + PAGE_MASK) / PAGE_SIZE;
    mapAcpiPages(physical_page, virtual_base, header_pages);

    const table_virtual_address = virtual_base + page_offset;
    const header_bytes = @as([*]const u8, @ptrFromInt(table_virtual_address))[0..acpi.SDT_HEADER_LENGTH];
    const length: usize = @intCast(acpi.sdtLengthFromHeader(header_bytes) catch return null);
    if (length < acpi.SDT_HEADER_LENGTH or length > MAX_ACPI_TABLE_BYTES) return null;
    const last_physical_address = std.math.add(u64, physical_address, length - 1) catch return null;
    if (last_physical_address > MAX_X86_PHYSICAL_ADDRESS) return null;
    const table_span = std.math.add(usize, page_offset, length) catch return null;
    const page_count = std.math.add(usize, table_span, PAGE_MASK) catch return null;
    mapAcpiPages(physical_page, virtual_base, page_count / PAGE_SIZE);
    return @as([*]const u8, @ptrFromInt(table_virtual_address))[0..length];
}

fn mapAcpiPages(physical_base: usize, virtual_base: usize, page_count: usize) void {
    var page_index: usize = 0;
    while (page_index < page_count) : (page_index += 1) {
        const page_offset = page_index * PAGE_SIZE;
        paging.mapKernelBorrowedPage(
            virtual_base + page_offset,
            physical_base + page_offset,
            paging.PAGE_PRESENT | paging.PAGE_CACHE_DISABLE,
        );
    }
}

fn printNewMarkers() void {
    if (facts.real_target_sku and !printed.source) {
        printMarker(hardware_target.nuc11tnki5_marker_prefix ++ ":EVIDENCE_SOURCE:REAL_HARDWARE");
        printed.source = true;
    }
    if (facts.real_target_sku and !printed.board) {
        printMarker(hardware_target.nuc11tnki5_marker_prefix ++ ":BOARD_SKU:NUC11TNKi5");
        printed.board = true;
    }
    if (facts.real_target_sku and !printed.smbios_sku) {
        printMarker(hardware_target.nuc11tnki5_marker_prefix ++ ":SMBIOS_SKU:OBSERVED");
        printed.smbios_sku = true;
    }
    if (facts.real_target_sku and facts.multiboot_handoff and facts.memory_map and !printed.multiboot_memory_map) {
        printMarker(hardware_target.nuc11tnki5_marker_prefix ++ ":MULTIBOOT_MEMORY_MAP:OBSERVED");
        printed.multiboot_memory_map = true;
    }
    if (facts.real_target_sku and facts.acpi_xsdt and !printed.acpi_xsdt) {
        printMarker(hardware_target.nuc11tnki5_marker_prefix ++ ":ACPI_XSDT:OBSERVED");
        printed.acpi_xsdt = true;
    }
    if (facts.real_target_sku and facts.acpi_madt and !printed.acpi_madt) {
        printMarker(hardware_target.nuc11tnki5_marker_prefix ++ ":ACPI_MADT:OBSERVED");
        printed.acpi_madt = true;
    }
    if (facts.real_target_sku and facts.acpi_fadt and !printed.acpi_fadt) {
        printMarker(hardware_target.nuc11tnki5_marker_prefix ++ ":ACPI_FADT:OBSERVED");
        printed.acpi_fadt = true;
    }
    if (facts.real_target_sku and facts.acpi_dmar and !printed.acpi_dmar) {
        printMarker(hardware_target.nuc11tnki5_marker_prefix ++ ":ACPI_DMAR:OBSERVED");
        printed.acpi_dmar = true;
    }
    if (facts.vtdDiscoveryReady() and !printed.vtd_segment_zero) {
        printMarker(hardware_target.nuc11tnki5_marker_prefix ++ ":VT_D_SEGMENT_ZERO:OBSERVED");
        printed.vtd_segment_zero = true;
    }
    if (facts.uefiBootReady() and !printed.uefi) {
        printMarker(hardware_target.nuc11tnki5_marker_prefix ++ ":UEFI_BOOT:PASS");
        printed.uefi = true;
    }
    if (facts.real_target_sku and facts.acpiTablesReady() and !printed.acpi_tables) {
        printMarker(hardware_target.nuc11tnki5_marker_prefix ++ ":ACPI_TABLES:PASS");
        printed.acpi_tables = true;
    }
    if (facts.vtdDiscoveryReady() and !printed.vtd_discovery) {
        printMarker(hardware_target.nuc11tnki5_marker_prefix ++ ":VT_D_DISCOVERY:PASS");
        printed.vtd_discovery = true;
    }
    if (facts.vtdStorageIsolationReady() and !printed.vtd_storage_isolation) {
        printMarker(hardware_target.nuc11tnki5_marker_prefix ++ ":VT_D_STORAGE_ISOLATION:ENFORCED");
        printed.vtd_storage_isolation = true;
    }
    if (facts.vtdInterruptIsolationReady() and !printed.vtd_interrupt_isolation) {
        printMarker(hardware_target.nuc11tnki5_marker_prefix ++ ":VT_D_INTERRUPT_ISOLATION:ENFORCED");
        printed.vtd_interrupt_isolation = true;
    }
    if (facts.vtdFaultProofReady() and !printed.vtd_blocked_dma_fault) {
        printMarker(hardware_target.nuc11tnki5_marker_prefix ++ ":VT_D_BLOCKED_DMA_FAULT:OBSERVED");
        printed.vtd_blocked_dma_fault = true;
    }
    if (facts.real_target_sku and facts.apic_timer and !printed.apic_timer) {
        if (!printed.apic_timer_interrupt) {
            printMarker(hardware_target.nuc11tnki5_marker_prefix ++ ":APIC_TIMER_INTERRUPT:OBSERVED");
            printed.apic_timer_interrupt = true;
        }
        printMarker(hardware_target.nuc11tnki5_marker_prefix ++ ":APIC_TIMER:PASS");
        printed.apic_timer = true;
    }
    if (facts.real_target_sku and facts.framebuffer_gop and !printed.framebuffer_gop) {
        if (!printed.framebuffer_scanout) {
            printMarker(hardware_target.nuc11tnki5_marker_prefix ++ ":FRAMEBUFFER_GOP_SCANOUT:OBSERVED");
            printed.framebuffer_scanout = true;
        }
        printMarker(hardware_target.nuc11tnki5_marker_prefix ++ ":FRAMEBUFFER_GOP:PASS");
        printed.framebuffer_gop = true;
    }
    if (facts.real_target_sku and facts.xhci_keyboard_input and !printed.xhci_input) {
        if (!printed.xhci_keyboard_report) {
            printMarker(hardware_target.nuc11tnki5_marker_prefix ++ ":XHCI_BOOT_KEYBOARD_REPORT:OBSERVED");
            printed.xhci_keyboard_report = true;
        }
        printMarker(hardware_target.nuc11tnki5_marker_prefix ++ ":USB_INPUT_XHCI:PASS");
        printed.xhci_input = true;
    }
    if (facts.real_target_sku and facts.nvmeBlockReady() and !printed.nvme_block) {
        if (!printed.nvme_write_read_completion) {
            printMarker(hardware_target.nuc11tnki5_marker_prefix ++ ":NVME_WRITE_READ_COMPLETION:OBSERVED");
            printed.nvme_write_read_completion = true;
        }
        printMarker(hardware_target.nuc11tnki5_marker_prefix ++ ":NVME_BLOCK:PASS");
        printed.nvme_block = true;
    }
    if (facts.real_target_sku and facts.i225PacketIoReady() and !printed.i225_packet_io) {
        if (!printed.i225_frame_interrupt) {
            printMarker(hardware_target.nuc11tnki5_marker_prefix ++ ":I225_LM_FRAME_INTERRUPT:OBSERVED");
            printed.i225_frame_interrupt = true;
        }
        printMarker(hardware_target.nuc11tnki5_marker_prefix ++ ":NETWORK_I225_LM:PASS");
        printed.i225_packet_io = true;
    }
    if (facts.real_target_sku and facts.suspendResumeReady() and !printed.suspend_resume) {
        if (!printed.suspend_resume_power) {
            printMarker(hardware_target.nuc11tnki5_marker_prefix ++ ":SUSPEND_RESUME_POWER:OBSERVED");
            printed.suspend_resume_power = true;
        }
        printMarker(hardware_target.nuc11tnki5_marker_prefix ++ ":SUSPEND_RESUME:PASS");
        printed.suspend_resume = true;
    }
    if (facts.real_target_sku and facts.crashRecoveryReady() and !printed.crash_recovery) {
        if (!printed.crash_record_reboot_persistence) {
            printMarker(hardware_target.nuc11tnki5_marker_prefix ++ ":CRASH_RECORD_REBOOT_PERSISTENCE:OBSERVED");
            printed.crash_record_reboot_persistence = true;
        }
        printMarker(hardware_target.nuc11tnki5_marker_prefix ++ ":CRASH_RECOVERY:PASS");
        printed.crash_recovery = true;
    }
    if (facts.real_target_sku and facts.updateRollbackReady() and !printed.update_rollback_power_cycle) {
        printMarker(hardware_target.nuc11tnki5_marker_prefix ++ ":UPDATE_ROLLBACK_POWER_CYCLE:OBSERVED");
        printed.update_rollback_power_cycle = true;
    }
    if (facts.real_target_sku and facts.attestationRootLifecycleFacts() != null and !printed.attestation_root_lifecycle) {
        printMarker(hardware_target.nuc11tnki5_marker_prefix ++ ":ATTESTATION_ROOT_LIFECYCLE:OBSERVED");
        printed.attestation_root_lifecycle = true;
    }
    printCounters();
}

fn printCounters() void {
    if (!facts.real_target_sku) return;
    const minimums = hardware_target.first_supported_target.proof_minimums;
    if (facts.cold_boots >= minimums.cold_boots and !printed.cold_boots) {
        printCounter("COLD_BOOTS", facts.cold_boots);
        printed.cold_boots = true;
    }
    if (facts.warm_reboots >= minimums.warm_reboots and !printed.warm_reboots) {
        printCounter("WARM_REBOOTS", facts.warm_reboots);
        printed.warm_reboots = true;
    }
    if (facts.storage_write_read_cycles >= minimums.storage_write_read_cycles and !printed.storage_cycles) {
        printCounter("STORAGE_WRITE_READ_CYCLES", facts.storage_write_read_cycles);
        printed.storage_cycles = true;
    }
    if (facts.network_frame_cycles >= minimums.network_frame_cycles and !printed.network_cycles) {
        printCounter("NETWORK_FRAME_CYCLES", facts.network_frame_cycles);
        printed.network_cycles = true;
    }
    if (facts.suspend_resume_cycles >= minimums.suspend_resume_cycles and !printed.suspend_cycles) {
        printCounter("SUSPEND_RESUME_CYCLES", facts.suspend_resume_cycles);
        printed.suspend_cycles = true;
    }
    if (facts.crash_recovery_cycles >= minimums.crash_recovery_cycles and !printed.crash_cycles) {
        printCounter("CRASH_RECOVERY_CYCLES", facts.crash_recovery_cycles);
        printed.crash_cycles = true;
    }
    if (facts.crash_record_persistence_cycles >= minimums.crash_record_persistence_cycles and !printed.crash_record_persistence_cycles) {
        printCounter("CRASH_RECORD_PERSISTENCE_CYCLES", facts.crash_record_persistence_cycles);
        printed.crash_record_persistence_cycles = true;
    }
    if (facts.update_rollback_cycles >= minimums.update_rollback_cycles and !printed.update_rollback_cycles) {
        printCounter("UPDATE_ROLLBACK_CYCLES", facts.update_rollback_cycles);
        printed.update_rollback_cycles = true;
    }
}

fn printMarker(marker: []const u8) void {
    if (builtin.is_test) return;
    console.print(marker);
    console.print("\n");
}

fn printCounter(name: []const u8, value: u16) void {
    if (builtin.is_test) return;
    console.print(hardware_target.nuc11tnki5_marker_prefix);
    console.print(":");
    console.print(name);
    console.print(":");
    printDec(value);
    console.print("\n");
}

fn printDec(value: u16) void {
    var remaining = value;
    var digits: [5]u8 = undefined;
    var count: usize = 0;
    if (remaining == 0) {
        console.printChar('0');
        return;
    }
    while (remaining > 0) : (remaining /= 10) {
        digits[count] = @as(u8, @intCast('0' + (remaining % 10)));
        count += 1;
    }
    while (count > 0) {
        count -= 1;
        console.printChar(digits[count]);
    }
}

fn testFadtFirmware() fadt.FixedAcpiDescription {
    return .{
        .revision = 6,
        .dsdt_address = 0x00AB_C000,
        .sci_interrupt = 9,
        .pm1a_event_block = 0x1800,
        .pm1b_event_block = 0,
        .pm1a_control_block = 0x1804,
        .pm1b_control_block = 0,
        .pm_timer_block = 0x1808,
        .pm1_event_length = 4,
        .pm1_control_length = 2,
        .pm_timer_length = 4,
        .reset_register = null,
        .reset_value = 0,
    };
}

fn testDmarSummary() dmar.Summary {
    var summary = dmar.Summary{
        .host_address_width = dmar.MIN_PRODUCTION_HOST_ADDRESS_WIDTH,
        .interrupt_remapping = true,
        .x2apic_opt_out = false,
        .dma_control_platform_opt_in = true,
        .dma_remapping_opt_out = false,
    };
    summary.remapping_units[0] = .{
        .register_base_address = 0xFED9_1000,
        .register_page_count = 1,
        .segment = 0,
        .include_pci_all = true,
    };
    summary.remapping_unit_count = 1;
    return summary;
}

test "hardware proof requires composed NUC subsystem evidence" {
    const target = &hardware_target.first_supported_target;
    const partial = ProbeFacts{
        .real_target_sku = true,
        .multiboot_handoff = true,
        .memory_map = true,
        .framebuffer_gop = true,
        .acpi_xsdt = true,
        .acpi_madt = true,
        .acpi_fadt = true,
        .acpi_mcfg = true,
        .acpi_dmar = true,
        .dmar_summary = testDmarSummary(),
        .apic_timer = true,
        .xhci_controller = true,
        .nvme_controller = true,
        .i225_lm_controller = true,
    };
    try std.testing.expect(partial.uefiBootReady());
    try std.testing.expect(partial.acpiTablesReady());
    var without_ecam = partial;
    without_ecam.acpi_mcfg = false;
    try std.testing.expect(!without_ecam.acpiTablesReady());
    var without_dmar = partial;
    without_dmar.acpi_dmar = false;
    try std.testing.expect(!without_dmar.acpiTablesReady());
    var opted_out = partial;
    var opted_out_summary = opted_out.dmar_summary.?;
    opted_out_summary.dma_remapping_opt_out = true;
    opted_out.dmar_summary = opted_out_summary;
    try std.testing.expect(!opted_out.vtdDiscoveryReady());
    try std.testing.expect(!allSubsystemMarkersReady(partial));
    try std.testing.expect(!hardware_target.hardwareProofSatisfied(target, evaluateEvidence(partial)));

    const complete = ProbeFacts{
        .real_target_sku = true,
        .multiboot_handoff = true,
        .memory_map = true,
        .framebuffer_gop = true,
        .acpi_xsdt = true,
        .acpi_madt = true,
        .acpi_fadt = true,
        .acpi_mcfg = true,
        .acpi_dmar = true,
        .dmar_summary = testDmarSummary(),
        .vtd_storage_isolation = true,
        .vtd_interrupt_isolation = true,
        .vtd_blocked_dma_fault = true,
        .apic_timer = true,
        .xhci_controller = true,
        .xhci_keyboard_input = true,
        .nvme_controller = true,
        .nvme_write_read_io = true,
        .i225_lm_controller = true,
        .i225_frame_io = true,
        .cold_boots = target.proof_minimums.cold_boots,
        .warm_reboots = target.proof_minimums.warm_reboots,
        .storage_write_read_cycles = target.proof_minimums.storage_write_read_cycles,
        .network_frame_cycles = target.proof_minimums.network_frame_cycles,
        .suspend_resume_power = true,
        .suspend_resume_cycles = target.proof_minimums.suspend_resume_cycles,
        .crash_recovery_record = true,
        .crash_recovery_cycles = target.proof_minimums.crash_recovery_cycles,
        .crash_record_persisted = true,
        .crash_record_persistence_cycles = target.proof_minimums.crash_record_persistence_cycles,
        .update_rollback_power_cycle = true,
        .update_rollback_cycles = target.proof_minimums.update_rollback_cycles,
    };
    try std.testing.expect(allSubsystemMarkersReady(complete));
    const runtime_evidence = evaluateEvidence(complete);
    try std.testing.expect(runtime_evidence.required_markers_captured);
    try std.testing.expect(!hardware_target.hardwareProofSatisfied(target, runtime_evidence));

    var archived_evidence = runtime_evidence;
    archived_evidence.proof_manifest_captured = true;
    archived_evidence.serial_log_captured = true;
    archived_evidence.firmware_settings_captured = true;
    archived_evidence.power_cycle_notes_captured = true;
    archived_evidence.artifact_digests_captured = true;
    try std.testing.expect(hardware_target.hardwareProofSatisfied(target, archived_evidence));
}

test "hardware proof records telemetry observations only with real target ACPI and matching generation" {
    resetForTest();
    recordThermalZoneSample(.{
        .reader_generation = 7,
        .zone_count = 1,
        .sample_sequence = 1,
        .thermal_milli_celsius = 61_000,
    });
    try std.testing.expectEqual(@as(u32, 0), factsForTest().telemetry_reader_generation);
    try std.testing.expect(factsForTest().thermalTelemetryFacts() == null);

    facts.real_target_sku = true;
    facts.acpi_fadt = true;
    facts.fadt_firmware = testFadtFirmware();
    facts.memory_capacity_bytes = 16 * 1024 * 1024;
    recordThermalZoneSample(.{
        .reader_generation = 7,
        .zone_count = 2,
        .sample_sequence = 11,
        .thermal_milli_celsius = 61_000,
    });
    recordBatteryStatusSample(.{
        .reader_generation = 8,
        .battery_device_count = 1,
        .sample_sequence = 12,
        .battery_percent = 44,
        .charging = true,
    });
    try std.testing.expect(factsForTest().batteryTelemetryFacts() == null);

    recordBatteryStatusSample(.{
        .reader_generation = 7,
        .battery_device_count = 1,
        .sample_sequence = 13,
        .battery_percent = 44,
        .charging = true,
    });
    recordAcceleratorDriverSample(.{
        .reader_generation = 7,
        .sample_sequence = 14,
        .gpu_driver_online = true,
        .media_driver_online = true,
        .gpu_driver_generation = 7,
        .media_driver_generation = 7,
        .completion_interrupts_observed = 2,
    });
    recordGridCarbonIntensitySample(.{
        .reader_generation = 7,
        .sample_sequence = 16,
        .grams_per_kwh = 215,
    });

    const recorded = factsForTest();
    try std.testing.expect(recorded.acpiTelemetryFacts() != null);
    try std.testing.expect(recorded.thermalTelemetryFacts() != null);
    try std.testing.expect(recorded.batteryTelemetryFacts() != null);
    try std.testing.expect(recorded.acceleratorTelemetryFacts() != null);
    try std.testing.expectEqual(@as(u32, 7), recorded.telemetry_reader_generation);
    try std.testing.expectEqual(@as(u16, 2), recorded.thermalTelemetryFacts().?.zone_count);
    try std.testing.expectEqual(@as(u8, 44), recorded.batteryTelemetryFacts().?.battery_percent);
    try std.testing.expect(recorded.gridCarbonTelemetryFacts() != null);
    try std.testing.expectEqual(@as(u16, 215), recorded.grid_carbon_intensity_grams_per_kwh);
    try std.testing.expectEqual(@as(u64, 16), recorded.gridCarbonTelemetryFacts().?.sample_sequence);
    try std.testing.expectEqual(@as(u16, 215), recorded.gridCarbonTelemetryFacts().?.grams_per_kwh);

    recordGridCarbonIntensitySample(.{
        .reader_generation = 7,
        .sample_sequence = 0,
        .grams_per_kwh = 300,
    });
    try std.testing.expectEqual(@as(u64, 16), factsForTest().gridCarbonTelemetryFacts().?.sample_sequence);

    recordAcceleratorDriverSample(.{
        .reader_generation = 7,
        .sample_sequence = 15,
        .gpu_driver_online = true,
        .gpu_driver_generation = 0,
        .completion_interrupts_observed = 1,
    });
    try std.testing.expectEqual(@as(u64, 14), factsForTest().acceleratorTelemetryFacts().?.sample_sequence);
}

test "hardware proof records APIC timer only from verified interrupt proof" {
    const summary = apic.Summary{
        .local_apic_address = 0xFEE0_0000,
        .pc_at_compatible = true,
        .processor_count = 1,
        .enabled_processor_count = 1,
        .io_apic_count = 1,
        .interrupt_source_override_count = 1,
    };
    const observation = apic.TimerInterruptObservation{
        .local_apic_address = summary.local_apic_address,
        .vector = 0x40,
        .initial_count = 10_000,
        .current_count_before = 8_000,
        .current_count_after = 6_000,
        .divide_value = 16,
        .mode = .periodic,
        .delivered_interrupts = 2,
        .eoi_count_before = 9,
        .eoi_count_after = 11,
    };
    const modeled_proof = try apic.proveTimerInterrupt(summary, observation);
    const hardware_proof = apic.withHardwareTimerEvidence(modeled_proof, .{
        .source = .hardware_lapic_timer,
        .initial_count_register_writes = 1,
        .divide_register_writes = 1,
        .lvt_timer_register_writes = 1,
        .current_count_register_reads = 2,
        .isr_vector_observations = 2,
        .interrupt_handler_entries = 2,
        .eoi_register_writes = 2,
        .tsc_delta_ticks = 100,
    });

    resetForTest();
    recordApicTimerProof(hardware_proof);
    try std.testing.expect(!factsForTest().apic_timer);

    resetForTest();
    facts.acpi_madt = true;
    recordApicTimerProof(modeled_proof);
    try std.testing.expect(!factsForTest().apic_timer);

    recordApicTimerProof(hardware_proof);
    try std.testing.expect(factsForTest().apic_timer);

    var malformed = hardware_proof;
    malformed.eoi_count = 0;
    resetForTest();
    facts.acpi_madt = true;
    recordApicTimerProof(malformed);
    try std.testing.expect(!factsForTest().apic_timer);
}

test "hardware proof records GOP framebuffer only from verified scanout proof" {
    const info = try framebuffer.validate(.{
        .physical_address = 0x8000_0000,
        .width = 64,
        .height = 16,
        .pixels_per_scan_line = 64,
        .format = .bgrx8888,
        .buffer_bytes = 64 * 16 * 4,
    });
    const expected_pixel: u32 = 0x00FF_00FF;
    var scanline = [_]u8{0} ** (64 * 4);
    std.mem.writeInt(u32, scanline[0..4], expected_pixel, .little);
    const modeled_proof = try framebuffer.proveScanout(info, scanline[0..], expected_pixel);
    const hardware_proof = framebuffer.withHardwareScanoutEvidence(modeled_proof, .{
        .source = .hardware_gop_scanout,
        .gop_mode_info_reads = 1,
        .framebuffer_base_observations = 1,
        .framebuffer_stride_observations = 1,
        .framebuffer_memory_read_bytes = scanline.len,
        .display_scanout_observations = 1,
        .expected_pixel_observations = 1,
        .captured_scanline_bytes = scanline.len,
        .sink_signal_observations = 1,
    });

    resetForTest();
    recordFramebufferProof(hardware_proof);
    try std.testing.expect(!factsForTest().framebuffer_gop);

    resetForTest();
    facts.multiboot_handoff = true;
    recordFramebufferProof(modeled_proof);
    try std.testing.expect(!factsForTest().framebuffer_gop);

    recordFramebufferProof(hardware_proof);
    try std.testing.expect(factsForTest().framebuffer_gop);

    var malformed = hardware_proof;
    malformed.expected_pixel_count = 0;
    resetForTest();
    facts.multiboot_handoff = true;
    recordFramebufferProof(malformed);
    try std.testing.expect(!factsForTest().framebuffer_gop);
}

test "hardware proof records xHCI input only from enumerated boot keyboard evidence" {
    var controller = try xhci.HidController.initWithMmio(xhci.defaultCapabilityRegisters(), .{
        .command_ring_trbs = 64,
        .event_ring_trbs = 64,
        .command_ring_address = 0x1000,
        .event_ring_address = 0x2000,
    });
    const descriptor = xhci.bootKeyboardConfigurationDescriptor(xhci.DEFAULT_BOOT_KEYBOARD_ENDPOINT_ID);
    const keyboard = try controller.attachBootKeyboard(xhci.DEFAULT_BOOT_KEYBOARD_DEVICE_ID, descriptor[0..]);
    const report = try xhci.bootKeyboardReport(keyboard.device_id, keyboard.endpoint_id, 0, &.{0x04});
    try controller.submitKeyboardInterruptEvent(keyboard.slot_id, keyboard.endpoint_id, report.reportSlice());
    const modeled_proof = controller.inputProof().?;
    const hardware_proof = xhci.withHardwareInputEvidence(modeled_proof, .{
        .source = .hardware_event_ring,
        .controller_event_trbs = 1,
        .event_ring_dma_writes = 1,
        .device_context_reads_by_controller = 1,
        .endpoint_context_reads_by_controller = 1,
        .interrupt_assertions = 1,
        .port_status_change_events = 1,
        .input_report_dma_bytes = xhci.HID_BOOT_KEYBOARD_REPORT_BYTES,
    });

    resetForTest();
    recordInputProof(hardware_proof);
    try std.testing.expect(!factsForTest().xhci_keyboard_input);

    resetForTest();
    facts.xhci_controller = true;
    recordInputProof(modeled_proof);
    try std.testing.expect(!factsForTest().xhci_keyboard_input);

    recordInputProof(hardware_proof);
    try std.testing.expect(factsForTest().xhci_keyboard_input);

    var malformed = hardware_proof;
    malformed.mmio.endpoint_context_writes = 0;
    resetForTest();
    facts.xhci_controller = true;
    recordInputProof(malformed);
    try std.testing.expect(!factsForTest().xhci_keyboard_input);
}

test "hardware proof records NVMe block cycles only from verified write read proof" {
    const cap = nvme.ControllerCapabilities{ .raw = (@as(u64, 63) | (@as(u64, 1) << 37)) };
    var image = [_]u8{0} ** (nvme.SECTOR_BYTES * 4);
    var namespaces = [_]nvme.Namespace{.{
        .id = 1,
        .sector_count = 4,
        .image = image[0..],
    }};
    var controller = try nvme.Controller.initWithMmio(
        cap,
        namespaces[0..],
        16,
        nvme.defaultAdminQueuePlan(),
        nvme.defaultProofPrp1Address(),
        nvme.SECTOR_BYTES,
    );
    const modeled_proof = try controller.proveWriteReadCycles(1, 0, 3);
    const hardware_proof = nvme.withHardwareCompletionEvidence(modeled_proof, .{
        .source = .hardware_dma,
        .controller_completion_writes = 6,
        .dma_read_bytes = 3 * nvme.SECTOR_BYTES,
        .dma_write_bytes = 3 * nvme.SECTOR_BYTES,
        .interrupt_count = 1,
        .phase_tag_observations = 6,
    });

    resetForTest();
    recordStorageProof(hardware_proof);
    try std.testing.expect(!factsForTest().nvme_write_read_io);
    try std.testing.expectEqual(@as(u16, 0), factsForTest().storage_write_read_cycles);

    resetForTest();
    facts.nvme_controller = true;
    recordStorageProof(modeled_proof);
    try std.testing.expect(!factsForTest().nvme_write_read_io);
    try std.testing.expectEqual(@as(u16, 0), factsForTest().storage_write_read_cycles);

    recordStorageProof(hardware_proof);
    try std.testing.expect(factsForTest().nvme_write_read_io);
    try std.testing.expectEqual(@as(u16, 3), factsForTest().storage_write_read_cycles);

    var malformed = hardware_proof;
    malformed.mmio.completed_commands = 0;
    resetForTest();
    facts.nvme_controller = true;
    recordStorageProof(malformed);
    try std.testing.expect(!factsForTest().nvme_write_read_io);
    try std.testing.expectEqual(@as(u16, 0), factsForTest().storage_write_read_cycles);
}

test "hardware proof records I225 network cycles only from verified packet proof" {
    var adapter = try intel_i225.SoftwareAdapter.initWithMmio(.{
        .rx_descriptors = 128,
        .tx_descriptors = 128,
        .rx_ring_address = 0x1000,
        .tx_ring_address = 0x2000,
    }, .{ 0x02, 0x15, 0xF2, 0, 0, 9 }, intel_i225.defaultPhyLinkState(), intel_i225.defaultPacketBufferPlan());
    const modeled_proof = try adapter.proveFrameCycles(4);
    const hardware_proof = intel_i225.withHardwarePacketEvidence(modeled_proof, .{
        .source = .hardware_descriptor_ring,
        .tx_descriptors_owned_by_device = 4,
        .rx_descriptors_owned_by_device = 4,
        .tx_dma_bytes = 4 * intel_i225.MIN_ETHERNET_FRAME_BYTES,
        .rx_dma_bytes = 4 * intel_i225.MIN_ETHERNET_FRAME_BYTES,
        .asserted_interrupts = 4,
        .phy_packet_observations = 4,
    });

    resetForTest();
    recordNetworkProof(hardware_proof);
    try std.testing.expect(!factsForTest().i225_frame_io);
    try std.testing.expectEqual(@as(u16, 0), factsForTest().network_frame_cycles);

    resetForTest();
    facts.i225_lm_controller = true;
    recordNetworkProof(modeled_proof);
    try std.testing.expect(!factsForTest().i225_frame_io);
    try std.testing.expectEqual(@as(u16, 0), factsForTest().network_frame_cycles);

    recordNetworkProof(hardware_proof);
    try std.testing.expect(factsForTest().i225_frame_io);
    try std.testing.expectEqual(@as(u16, 4), factsForTest().network_frame_cycles);

    var malformed = hardware_proof;
    malformed.mmio.interrupt_cause_reads = 0;
    resetForTest();
    facts.i225_lm_controller = true;
    recordNetworkProof(malformed);
    try std.testing.expect(!factsForTest().i225_frame_io);
    try std.testing.expectEqual(@as(u16, 0), factsForTest().network_frame_cycles);
}

test "hardware proof records suspend resume only from ACPI backed resume proof" {
    const firmware = fadt.FixedAcpiDescription{
        .revision = 6,
        .dsdt_address = 0x00AB_C000,
        .sci_interrupt = 9,
        .pm1a_event_block = 0x1800,
        .pm1b_event_block = 0,
        .pm1a_control_block = 0x1804,
        .pm1b_control_block = 0,
        .pm_timer_block = 0x1808,
        .pm1_event_length = 4,
        .pm1_control_length = 2,
        .pm_timer_length = 4,
        .reset_register = null,
        .reset_value = 0,
    };
    const modeled_proof = try fadt.proveSuspendResume(firmware, 3, 10, 40, 3, .{
        .timer = true,
        .framebuffer = true,
        .xhci_input = true,
        .nvme_block = true,
        .i225_network = true,
    });
    const hardware_proof = fadt.withHardwareSuspendResumeEvidence(modeled_proof, .{
        .source = .hardware_power_transition,
        .pm1_control_sleep_writes = 3,
        .s_state_entry_observations = 3,
        .s0_resume_observations = 3,
        .pm_timer_resume_reads = 6,
        .sci_wake_interrupts = 3,
        .resumed_timer_probes = 3,
        .resumed_framebuffer_probes = 3,
        .resumed_xhci_probes = 3,
        .resumed_nvme_probes = 3,
        .resumed_i225_probes = 3,
    });

    resetForTest();
    recordSuspendResumeProof(hardware_proof);
    try std.testing.expect(!factsForTest().suspend_resume_power);
    try std.testing.expectEqual(@as(u16, 0), factsForTest().suspend_resume_cycles);

    resetForTest();
    facts.acpi_fadt = true;
    recordSuspendResumeProof(modeled_proof);
    try std.testing.expect(!factsForTest().suspend_resume_power);
    try std.testing.expectEqual(@as(u16, 0), factsForTest().suspend_resume_cycles);

    recordSuspendResumeProof(hardware_proof);
    try std.testing.expect(factsForTest().suspend_resume_power);
    try std.testing.expectEqual(@as(u16, 3), factsForTest().suspend_resume_cycles);

    var malformed = hardware_proof;
    malformed.wake_sci_count = 0;
    resetForTest();
    facts.acpi_fadt = true;
    recordSuspendResumeProof(malformed);
    try std.testing.expect(!factsForTest().suspend_resume_power);
    try std.testing.expectEqual(@as(u16, 0), factsForTest().suspend_resume_cycles);
}

test "hardware proof records crash recovery and persistence only from validated crash record proof" {
    const record = try crash_record.init(.watchdog, 77, 88, 0x1234, 0x5678, "capability token leaked");
    var report_buffer: [crash_record.REDACTED_REPORT_BUFFER_BYTES]u8 = undefined;
    const modeled_proof = try crash_record.provePersistence(record, record, 78, 4, report_buffer[0..]);
    const hardware_proof = crash_record.withHardwarePersistenceEvidence(modeled_proof, .{
        .source = .hardware_reboot_persistence,
        .crash_handler_entries = 4,
        .persistent_record_writes = 4,
        .persistent_record_flushes = 4,
        .reboot_observations = 4,
        .recovery_boot_reads = 4,
        .recovered_record_validations = 4,
        .redacted_report_emissions = 4,
        .persistent_bytes_written = 4 * @sizeOf(crash_record.Record),
        .persistent_bytes_read = 4 * @sizeOf(crash_record.Record),
    });

    resetForTest();
    recordCrashPersistenceProof(modeled_proof);
    try std.testing.expect(!factsForTest().crash_recovery_record);
    try std.testing.expect(!factsForTest().crash_record_persisted);
    try std.testing.expectEqual(@as(u16, 0), factsForTest().crash_recovery_cycles);
    try std.testing.expectEqual(@as(u16, 0), factsForTest().crash_record_persistence_cycles);

    recordCrashPersistenceProof(hardware_proof);
    try std.testing.expect(factsForTest().crash_recovery_record);
    try std.testing.expect(factsForTest().crash_record_persisted);
    try std.testing.expectEqual(@as(u16, 4), factsForTest().crash_recovery_cycles);
    try std.testing.expectEqual(@as(u16, 4), factsForTest().crash_record_persistence_cycles);

    var malformed = hardware_proof;
    malformed.recovered_record.tick += 1;
    resetForTest();
    recordCrashPersistenceProof(malformed);
    try std.testing.expect(!factsForTest().crash_recovery_record);
    try std.testing.expect(!factsForTest().crash_record_persisted);
    try std.testing.expectEqual(@as(u16, 0), factsForTest().crash_recovery_cycles);
    try std.testing.expectEqual(@as(u16, 0), factsForTest().crash_record_persistence_cycles);
}

test "hardware proof records update rollback only from verified power cycle proof" {
    const modeled_proof = hardware_target.UpdateRollbackProof{
        .cycles = 5,
        .stable_slot = 0,
        .candidate_slot = 1,
        .recovered_slot = 0,
        .activation_generation_before = 10,
        .activation_generation_after = 11,
        .rollback_generation_before = 3,
        .rollback_generation_after = 4,
        .failure_detected = true,
        .rollback_decision = true,
        .service_use_started = false,
        .selector_record_persisted = true,
        .post_power_cycle_verified = true,
        .active_slot_verified = true,
        .persisted_state_preserved = true,
    };
    const hardware_proof = hardware_target.withHardwareUpdateRollbackEvidence(modeled_proof, .{
        .source = .hardware_power_cycle,
        .candidate_activation_writes = 5,
        .selector_record_flushes = 5,
        .power_cycle_observations = 5,
        .failure_detector_observations = 5,
        .rollback_decision_records = 5,
        .stable_slot_boot_observations = 5,
        .recovered_slot_reads = 5,
        .persisted_state_verifications = 5,
        .service_start_suppression_observations = 5,
    });

    resetForTest();
    recordUpdateRollbackProof(modeled_proof);
    try std.testing.expect(!factsForTest().update_rollback_power_cycle);
    try std.testing.expectEqual(@as(u16, 0), factsForTest().update_rollback_cycles);

    recordUpdateRollbackProof(hardware_proof);
    try std.testing.expect(factsForTest().update_rollback_power_cycle);
    try std.testing.expectEqual(@as(u16, 5), factsForTest().update_rollback_cycles);

    var malformed = hardware_proof;
    malformed.recovered_slot = malformed.candidate_slot;
    resetForTest();
    recordUpdateRollbackProof(malformed);
    try std.testing.expect(!factsForTest().update_rollback_power_cycle);
    try std.testing.expectEqual(@as(u16, 0), factsForTest().update_rollback_cycles);
}

test "hardware proof records attestation root lifecycle only from complete real target evidence" {
    const proof = AttestationRootLifecycleProof{
        .source = .real_hardware,
        .initial_generation = 7,
        .active_generation = 9,
        .revoked_generation_count = 1,
        .stale_generation_rejected = true,
        .revoked_generation_rejected = true,
        .verifier_rejected_stale_attestation = true,
        .verifier_metadata_digest_bound = true,
    };

    resetForTest();
    try std.testing.expect(recordAttestationRootLifecycleProof(proof));
    const recorded = factsForTest();
    try std.testing.expect(recorded.real_target_sku);
    const lifecycle = recorded.attestationRootLifecycleFacts();
    try std.testing.expect(lifecycle != null);
    try std.testing.expect(printed.attestation_root_lifecycle);
    try std.testing.expectEqual(@as(u64, 7), lifecycle.?.initial_generation);
    try std.testing.expectEqual(@as(u64, 9), lifecycle.?.active_generation);
    try std.testing.expectEqual(@as(u8, 1), lifecycle.?.revoked_generation_count);

    var qemu_proof = proof;
    qemu_proof.source = .qemu;
    resetForTest();
    try std.testing.expect(!recordAttestationRootLifecycleProof(qemu_proof));
    try std.testing.expect(factsForTest().attestationRootLifecycleFacts() == null);

    var stale_rotation = proof;
    stale_rotation.active_generation = stale_rotation.initial_generation;
    resetForTest();
    try std.testing.expect(!recordAttestationRootLifecycleProof(stale_rotation));
    try std.testing.expect(factsForTest().attestationRootLifecycleFacts() == null);

    var missing_revocation = proof;
    missing_revocation.revoked_generation_count = 0;
    resetForTest();
    try std.testing.expect(!recordAttestationRootLifecycleProof(missing_revocation));
    try std.testing.expect(factsForTest().attestationRootLifecycleFacts() == null);

    var missing_stale_rejection = proof;
    missing_stale_rejection.verifier_rejected_stale_attestation = false;
    resetForTest();
    try std.testing.expect(!recordAttestationRootLifecycleProof(missing_stale_rejection));
    try std.testing.expect(factsForTest().attestationRootLifecycleFacts() == null);

    var missing_metadata_binding = proof;
    missing_metadata_binding.verifier_metadata_digest_bound = false;
    resetForTest();
    try std.testing.expect(!recordAttestationRootLifecycleProof(missing_metadata_binding));
    try std.testing.expect(factsForTest().attestationRootLifecycleFacts() == null);
}
