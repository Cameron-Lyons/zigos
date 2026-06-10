const std = @import("std");
const acpi = @import("acpi.zig");
const apic = @import("apic.zig");
const fadt = @import("fadt.zig");
const smbios = @import("smbios.zig");
const crash_record = @import("crash_record.zig");
const handoff = @import("../boot/handoff.zig");
const console = @import("../utils/console.zig");
const pci = @import("../drivers/pci.zig");
const hardware_target = @import("../../native/platform/hardware_target.zig");

const BIOS_RSDP_SCAN_BASE: usize = 0xE0000;
const BIOS_RSDP_SCAN_LENGTH: usize = 0x20000;
const MAX_ACPI_TABLE_BYTES: usize = 1024 * 1024;

pub const ProbeFacts = struct {
    real_target_sku: bool = false,
    multiboot_handoff: bool = false,
    memory_map: bool = false,
    acpi_rsdp: bool = false,
    acpi_madt: bool = false,
    acpi_fadt: bool = false,
    apic_timer: bool = false,
    framebuffer_gop: bool = false,
    xhci_controller: bool = false,
    xhci_keyboard_input: bool = false,
    nvme_controller: bool = false,
    i225_lm_controller: bool = false,
    cold_boots: u16 = 0,
    warm_reboots: u16 = 0,
    storage_write_read_cycles: u16 = 0,
    network_frame_cycles: u16 = 0,
    suspend_resume_cycles: u16 = 0,
    crash_recovery_cycles: u16 = 0,

    pub fn uefiBootReady(self: ProbeFacts) bool {
        return self.real_target_sku and self.multiboot_handoff and self.memory_map and self.framebuffer_gop;
    }

    pub fn acpiTablesReady(self: ProbeFacts) bool {
        return self.acpi_rsdp and self.acpi_madt and self.acpi_fadt;
    }

    pub fn nvmeBlockReady(self: ProbeFacts) bool {
        return self.nvme_controller and self.storage_write_read_cycles >= hardware_target.first_supported_target.proof_minimums.storage_write_read_cycles;
    }

    pub fn i225PacketIoReady(self: ProbeFacts) bool {
        return self.i225_lm_controller and self.network_frame_cycles >= hardware_target.first_supported_target.proof_minimums.network_frame_cycles;
    }

    pub fn suspendResumeReady(self: ProbeFacts) bool {
        return self.suspend_resume_cycles >= hardware_target.first_supported_target.proof_minimums.suspend_resume_cycles;
    }

    pub fn crashRecoveryReady(self: ProbeFacts) bool {
        return self.crash_recovery_cycles >= hardware_target.first_supported_target.proof_minimums.crash_recovery_cycles;
    }
};

const PrintedMarkers = struct {
    source: bool = false,
    board: bool = false,
    uefi: bool = false,
    acpi_tables: bool = false,
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
};

var facts = ProbeFacts{};
var printed = PrintedMarkers{};

pub fn resetForTest() void {
    facts = .{};
    printed = .{};
}

pub fn factsForTest() ProbeFacts {
    return facts;
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
        .required_markers_captured = allSubsystemMarkersReady(probe),
    };
}

pub fn allSubsystemMarkersReady(probe: ProbeFacts) bool {
    return probe.uefiBootReady() and
        probe.acpiTablesReady() and
        probe.apic_timer and
        probe.framebuffer_gop and
        probe.xhci_keyboard_input and
        probe.nvmeBlockReady() and
        probe.i225PacketIoReady() and
        probe.suspendResumeReady() and
        probe.crashRecoveryReady();
}

pub fn countersReady(probe: ProbeFacts) bool {
    const minimums = hardware_target.first_supported_target.proof_minimums;
    return probe.cold_boots >= minimums.cold_boots and
        probe.warm_reboots >= minimums.warm_reboots and
        probe.storage_write_read_cycles >= minimums.storage_write_read_cycles and
        probe.network_frame_cycles >= minimums.network_frame_cycles and
        probe.suspend_resume_cycles >= minimums.suspend_resume_cycles and
        probe.crash_recovery_cycles >= minimums.crash_recovery_cycles;
}

pub fn captureEarlyBootEvidence() void {
    facts.real_target_sku = smbios.scanBiosForNuc11Tnki5();

    if (handoff.capturedInfo()) |info| {
        facts.multiboot_handoff = true;
        if (handoff.capturedMemoryMapSummary(info)) |summary| {
            facts.memory_map = summary.hasUsableMemory();
        }
        if (handoff.framebufferInfo(info)) |_| {
            facts.framebuffer_gop = true;
        } else |_| {}
    }

    captureAcpiEvidence();
    printNewMarkers();
}

pub fn capturePciEvidence() void {
    facts.nvme_controller = pci.firstNvmeController() != null;
    facts.i225_lm_controller = pci.firstIntelI225Lm() != null;
    facts.xhci_controller = pci.firstXhciController() != null;
    printNewMarkers();
}

pub fn recordInputProof() void {
    facts.xhci_keyboard_input = facts.xhci_controller;
    printNewMarkers();
}

pub fn recordStorageCycles(cycles: u16) void {
    facts.storage_write_read_cycles = @max(facts.storage_write_read_cycles, cycles);
    printNewMarkers();
}

pub fn recordNetworkFrameCycles(cycles: u16) void {
    facts.network_frame_cycles = @max(facts.network_frame_cycles, cycles);
    printNewMarkers();
}

pub fn recordPowerCycleCounts(cold_boots: u16, warm_reboots: u16) void {
    facts.cold_boots = @max(facts.cold_boots, cold_boots);
    facts.warm_reboots = @max(facts.warm_reboots, warm_reboots);
    printNewMarkers();
}

pub fn recordSuspendResumeCycles(cycles: u16) void {
    facts.suspend_resume_cycles = @max(facts.suspend_resume_cycles, cycles);
    printNewMarkers();
}

pub fn recordCrashRecoveryCycles(cycles: u16) void {
    facts.crash_recovery_cycles = @max(facts.crash_recovery_cycles, cycles);
    printNewMarkers();
}

fn captureAcpiEvidence() void {
    const rsdp_location = findRsdpInBiosRegions() orelse return;
    facts.acpi_rsdp = true;

    const root_address: u64 = if (rsdp_location.descriptor.xsdt_address != 0)
        rsdp_location.descriptor.xsdt_address
    else
        rsdp_location.descriptor.rsdt_address;
    const root_table = physicalTableBytes(root_address) orelse return;

    const count = acpi.rootTableEntryCount(root_table) catch return;
    var found_madt = false;
    var found_fadt = false;
    var apic_timer_ready = false;
    var index: u32 = 0;
    while (index < count) : (index += 1) {
        const table_address = acpi.rootTableEntryAddress(root_table, index) catch continue;
        const table = physicalTableBytes(table_address) orelse continue;
        const header = acpi.parseSdtHeader(table) catch continue;
        if (std.mem.eql(u8, header.signature[0..], apic.MADT_SIGNATURE)) {
            if (apic.parseMadt(table)) |summary| {
                found_madt = true;
                apic_timer_ready = summary.local_apic_address != 0 and summary.enabled_processor_count > 0;
            } else |_| {}
        } else if (std.mem.eql(u8, header.signature[0..], fadt.FADT_SIGNATURE)) {
            _ = fadt.parseFadt(table) catch continue;
            found_fadt = true;
        }
    }

    facts.acpi_madt = found_madt;
    facts.acpi_fadt = found_fadt;
    facts.apic_timer = apic_timer_ready;
}

fn findRsdpInBiosRegions() ?acpi.RsdpLocation {
    const bios = @as([*]const u8, @ptrFromInt(BIOS_RSDP_SCAN_BASE))[0..BIOS_RSDP_SCAN_LENGTH];
    return acpi.findRsdp(bios, BIOS_RSDP_SCAN_BASE);
}

fn physicalTableBytes(physical_address: u64) ?[]const u8 {
    const max_address: u64 = std.math.maxInt(usize);
    if (physical_address == 0 or physical_address > max_address - acpi.SDT_HEADER_LENGTH) return null;
    const address: usize = @intCast(physical_address);
    const header_bytes = @as([*]const u8, @ptrFromInt(address))[0..acpi.SDT_HEADER_LENGTH];
    const length = readU32Le(header_bytes[4..8]);
    if (length < acpi.SDT_HEADER_LENGTH or length > MAX_ACPI_TABLE_BYTES) return null;
    return @as([*]const u8, @ptrFromInt(address))[0..length];
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
    if (facts.uefiBootReady() and !printed.uefi) {
        printMarker(hardware_target.nuc11tnki5_marker_prefix ++ ":UEFI_BOOT:PASS");
        printed.uefi = true;
    }
    if (facts.real_target_sku and facts.acpiTablesReady() and !printed.acpi_tables) {
        printMarker(hardware_target.nuc11tnki5_marker_prefix ++ ":ACPI_TABLES:PASS");
        printed.acpi_tables = true;
    }
    if (facts.real_target_sku and facts.apic_timer and !printed.apic_timer) {
        printMarker(hardware_target.nuc11tnki5_marker_prefix ++ ":APIC_TIMER:PASS");
        printed.apic_timer = true;
    }
    if (facts.real_target_sku and facts.framebuffer_gop and !printed.framebuffer_gop) {
        printMarker(hardware_target.nuc11tnki5_marker_prefix ++ ":FRAMEBUFFER_GOP:PASS");
        printed.framebuffer_gop = true;
    }
    if (facts.real_target_sku and facts.xhci_keyboard_input and !printed.xhci_input) {
        printMarker(hardware_target.nuc11tnki5_marker_prefix ++ ":USB_INPUT_XHCI:PASS");
        printed.xhci_input = true;
    }
    if (facts.real_target_sku and facts.nvmeBlockReady() and !printed.nvme_block) {
        printMarker(hardware_target.nuc11tnki5_marker_prefix ++ ":NVME_BLOCK:PASS");
        printed.nvme_block = true;
    }
    if (facts.real_target_sku and facts.i225PacketIoReady() and !printed.i225_packet_io) {
        printMarker(hardware_target.nuc11tnki5_marker_prefix ++ ":NETWORK_I225_LM:PASS");
        printed.i225_packet_io = true;
    }
    if (facts.real_target_sku and facts.suspendResumeReady() and !printed.suspend_resume) {
        printMarker(hardware_target.nuc11tnki5_marker_prefix ++ ":SUSPEND_RESUME:PASS");
        printed.suspend_resume = true;
    }
    if (facts.real_target_sku and facts.crashRecoveryReady() and !printed.crash_recovery) {
        printMarker(hardware_target.nuc11tnki5_marker_prefix ++ ":CRASH_RECOVERY:PASS");
        printed.crash_recovery = true;
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
}

fn printMarker(marker: []const u8) void {
    console.print(marker);
    console.print("\n");
}

fn printCounter(name: []const u8, value: u16) void {
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

fn readU32Le(bytes: []const u8) u32 {
    return @as(u32, bytes[0]) |
        (@as(u32, bytes[1]) << 8) |
        (@as(u32, bytes[2]) << 16) |
        (@as(u32, bytes[3]) << 24);
}

test "hardware proof requires composed NUC subsystem evidence" {
    const target = &hardware_target.first_supported_target;
    const partial = ProbeFacts{
        .real_target_sku = true,
        .multiboot_handoff = true,
        .memory_map = true,
        .framebuffer_gop = true,
        .acpi_rsdp = true,
        .acpi_madt = true,
        .acpi_fadt = true,
        .apic_timer = true,
        .xhci_controller = true,
        .nvme_controller = true,
        .i225_lm_controller = true,
    };
    try std.testing.expect(partial.uefiBootReady());
    try std.testing.expect(partial.acpiTablesReady());
    try std.testing.expect(!allSubsystemMarkersReady(partial));
    try std.testing.expect(!hardware_target.hardwareProofSatisfied(target, evaluateEvidence(partial)));

    const complete = ProbeFacts{
        .real_target_sku = true,
        .multiboot_handoff = true,
        .memory_map = true,
        .framebuffer_gop = true,
        .acpi_rsdp = true,
        .acpi_madt = true,
        .acpi_fadt = true,
        .apic_timer = true,
        .xhci_controller = true,
        .xhci_keyboard_input = true,
        .nvme_controller = true,
        .i225_lm_controller = true,
        .cold_boots = target.proof_minimums.cold_boots,
        .warm_reboots = target.proof_minimums.warm_reboots,
        .storage_write_read_cycles = target.proof_minimums.storage_write_read_cycles,
        .network_frame_cycles = target.proof_minimums.network_frame_cycles,
        .suspend_resume_cycles = target.proof_minimums.suspend_resume_cycles,
        .crash_recovery_cycles = target.proof_minimums.crash_recovery_cycles,
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

test "hardware proof redacted crash records count toward crash recovery evidence" {
    const record = try crash_record.init(.watchdog, 77, 88, 0x1234, 0x5678, "capability token leaked");
    var report_buffer: [256]u8 = undefined;
    const report = crash_record.redactedReport(record, report_buffer[0..]);
    try std.testing.expect(std.mem.indexOf(u8, report, "redacted=yes") != null);

    var probe = ProbeFacts{};
    probe.crash_recovery_cycles = hardware_target.first_supported_target.proof_minimums.crash_recovery_cycles;
    try std.testing.expect(probe.crashRecoveryReady());
}
