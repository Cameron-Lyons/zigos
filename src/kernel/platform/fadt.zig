const std = @import("std");
const acpi = @import("acpi.zig");
const endian = @import("../utils/endian.zig");
const checksum = @import("../utils/checksum.zig");

const finishChecksum = checksum.finishSum8Prefix;
const readU16Le = endian.readU16Le;
const readU32Le = endian.readU32Le;
const readU64Le = endian.readU64Le;
const writeU16Le = endian.writeU16Le;
const writeU32Le = endian.writeU32Le;
const writeU64Le = endian.writeU64Le;

pub const FADT_SIGNATURE = "FACP";
pub const SDT_HEADER_LENGTH: usize = acpi.SDT_HEADER_LENGTH;
pub const MIN_FADT_PM_LENGTH: usize = 96;
const FADT_TEST_TABLE_BYTES: usize = 132;
const FADT_REVISION_OFFSET: usize = 8;
const FADT_DSDT_OFFSET: usize = 40;
const FADT_SCI_INTERRUPT_OFFSET: usize = 46;
const FADT_PM1A_EVENT_BLOCK_OFFSET: usize = 56;
const FADT_PM1B_EVENT_BLOCK_OFFSET: usize = 60;
const FADT_PM1A_CONTROL_BLOCK_OFFSET: usize = 64;
const FADT_PM1B_CONTROL_BLOCK_OFFSET: usize = 68;
const FADT_PM_TIMER_BLOCK_OFFSET: usize = 76;
const FADT_PM1_EVENT_LENGTH_OFFSET: usize = 88;
const FADT_PM1_CONTROL_LENGTH_OFFSET: usize = 89;
const FADT_PM_TIMER_LENGTH_OFFSET: usize = 91;
const MIN_PM1_CONTROL_LENGTH: u8 = 2;
pub const RESET_REGISTER_OFFSET: usize = 116;
pub const RESET_VALUE_OFFSET: usize = 128;
pub const GENERIC_ADDRESS_STRUCTURE_BYTES: usize = 12;
const GAS_ADDRESS_OFFSET: usize = 4;

pub const Error = error{
    TooSmall,
    BadSignature,
    BadChecksum,
    InvalidLength,
    MissingPmControlBlock,
    InvalidPmControlLength,
    MissingPmEventBlock,
    MissingPmTimer,
    MissingSciInterrupt,
    SuspendResumeCycleCountInvalid,
    PmTimerDidNotAdvance,
    WakeInterruptMissing,
    ResumeSubsystemMissing,
};

pub const GenericAddress = struct {
    address_space_id: u8,
    register_bit_width: u8,
    register_bit_offset: u8,
    access_size: u8,
    address: u64,
};

pub const FixedAcpiDescription = struct {
    revision: u8,
    dsdt_address: u64,
    sci_interrupt: u16,
    pm1a_event_block: u32,
    pm1b_event_block: u32,
    pm1a_control_block: u32,
    pm1b_control_block: u32,
    pm_timer_block: u32,
    pm1_event_length: u8,
    pm1_control_length: u8,
    pm_timer_length: u8,
    reset_register: ?GenericAddress,
    reset_value: u8,
};

pub const ResumeSubsystems = struct {
    timer: bool = false,
    framebuffer: bool = false,
    xhci_input: bool = false,
    nvme_block: bool = false,
    i225_network: bool = false,

    pub fn allReady(self: ResumeSubsystems) bool {
        return self.timer and
            self.framebuffer and
            self.xhci_input and
            self.nvme_block and
            self.i225_network;
    }
};

pub const SuspendEvidenceSource = enum(u8) {
    modeled_acpi,
    hardware_power_transition,
};

pub const HardwareSuspendResumeEvidence = struct {
    source: SuspendEvidenceSource = .modeled_acpi,
    pm1_control_sleep_writes: u32 = 0,
    s_state_entry_observations: u32 = 0,
    s0_resume_observations: u32 = 0,
    pm_timer_resume_reads: u32 = 0,
    sci_wake_interrupts: u32 = 0,
    resumed_timer_probes: u32 = 0,
    resumed_framebuffer_probes: u32 = 0,
    resumed_xhci_probes: u32 = 0,
    resumed_nvme_probes: u32 = 0,
    resumed_i225_probes: u32 = 0,

    pub fn verified(self: HardwareSuspendResumeEvidence, proof: SuspendResumeProof) bool {
        const expected_cycles = @as(u32, proof.cycles);
        const expected_timer_reads = std.math.mul(u32, expected_cycles, 2) catch return false;
        return self.source == .hardware_power_transition and
            expected_cycles > 0 and
            self.pm1_control_sleep_writes >= expected_cycles and
            self.s_state_entry_observations >= expected_cycles and
            self.s0_resume_observations >= expected_cycles and
            self.pm_timer_resume_reads >= expected_timer_reads and
            self.sci_wake_interrupts >= expected_cycles and
            self.resumed_timer_probes >= expected_cycles and
            self.resumed_framebuffer_probes >= expected_cycles and
            self.resumed_xhci_probes >= expected_cycles and
            self.resumed_nvme_probes >= expected_cycles and
            self.resumed_i225_probes >= expected_cycles;
    }
};

pub const SuspendResumeProof = struct {
    firmware: FixedAcpiDescription,
    cycles: u16,
    pm_timer_before: u32,
    pm_timer_after: u32,
    wake_sci_count: u16,
    resumed: ResumeSubsystems,
    hardware_resume: HardwareSuspendResumeEvidence = .{},

    pub fn verified(self: SuspendResumeProof) bool {
        return firmwareSupportsSuspendResume(self.firmware) and
            self.cycles > 0 and
            self.pm_timer_after != self.pm_timer_before and
            self.wake_sci_count >= self.cycles and
            self.resumed.allReady();
    }

    pub fn productionHardwareVerified(self: SuspendResumeProof) bool {
        return self.verified() and self.hardware_resume.verified(self);
    }
};

pub fn parseFadt(table: []const u8) Error!FixedAcpiDescription {
    if (table.len < MIN_FADT_PM_LENGTH) return error.TooSmall;
    if (!std.mem.eql(u8, table[0..FADT_SIGNATURE.len], FADT_SIGNATURE)) return error.BadSignature;

    const sdt = try acpi.parseSdtHeader(table);
    const table_length = sdt.length;
    if (table_length < MIN_FADT_PM_LENGTH or table_length > table.len) return error.InvalidLength;

    const pm1a_control_block = readU32Le(table[FADT_PM1A_CONTROL_BLOCK_OFFSET..][0..4]);
    const pm1b_control_block = readU32Le(table[FADT_PM1B_CONTROL_BLOCK_OFFSET..][0..4]);
    const pm1_control_length = table[FADT_PM1_CONTROL_LENGTH_OFFSET];
    if (pm1a_control_block == 0 and pm1b_control_block == 0) return error.MissingPmControlBlock;
    if (pm1_control_length < MIN_PM1_CONTROL_LENGTH) return error.InvalidPmControlLength;

    return .{
        .revision = table[FADT_REVISION_OFFSET],
        .dsdt_address = readU32Le(table[FADT_DSDT_OFFSET..][0..4]),
        .sci_interrupt = readU16Le(table[FADT_SCI_INTERRUPT_OFFSET..][0..2]),
        .pm1a_event_block = readU32Le(table[FADT_PM1A_EVENT_BLOCK_OFFSET..][0..4]),
        .pm1b_event_block = readU32Le(table[FADT_PM1B_EVENT_BLOCK_OFFSET..][0..4]),
        .pm1a_control_block = pm1a_control_block,
        .pm1b_control_block = pm1b_control_block,
        .pm_timer_block = readU32Le(table[FADT_PM_TIMER_BLOCK_OFFSET..][0..4]),
        .pm1_event_length = table[FADT_PM1_EVENT_LENGTH_OFFSET],
        .pm1_control_length = pm1_control_length,
        .pm_timer_length = table[FADT_PM_TIMER_LENGTH_OFFSET],
        .reset_register = parseResetRegister(table[0..table_length]),
        .reset_value = if (table_length > RESET_VALUE_OFFSET) table[RESET_VALUE_OFFSET] else 0,
    };
}

pub fn proveSuspendResume(
    firmware: FixedAcpiDescription,
    cycles: u16,
    pm_timer_before: u32,
    pm_timer_after: u32,
    wake_sci_count: u16,
    resumed: ResumeSubsystems,
) Error!SuspendResumeProof {
    if (cycles == 0) return error.SuspendResumeCycleCountInvalid;
    if (firmware.pm1a_event_block == 0 and firmware.pm1b_event_block == 0) return error.MissingPmEventBlock;
    if (firmware.pm_timer_block == 0 or firmware.pm_timer_length == 0) return error.MissingPmTimer;
    if (firmware.sci_interrupt == 0) return error.MissingSciInterrupt;
    if (firmware.pm1a_control_block == 0 and firmware.pm1b_control_block == 0) return error.MissingPmControlBlock;
    if (firmware.pm1_control_length < MIN_PM1_CONTROL_LENGTH) return error.InvalidPmControlLength;
    if (pm_timer_after == pm_timer_before) return error.PmTimerDidNotAdvance;
    if (wake_sci_count < cycles) return error.WakeInterruptMissing;
    if (!resumed.allReady()) return error.ResumeSubsystemMissing;
    return .{
        .firmware = firmware,
        .cycles = cycles,
        .pm_timer_before = pm_timer_before,
        .pm_timer_after = pm_timer_after,
        .wake_sci_count = wake_sci_count,
        .resumed = resumed,
    };
}

fn parseResetRegister(table: []const u8) ?GenericAddress {
    if (table.len < RESET_REGISTER_OFFSET + GENERIC_ADDRESS_STRUCTURE_BYTES) return null;
    const gas = table[RESET_REGISTER_OFFSET .. RESET_REGISTER_OFFSET + GENERIC_ADDRESS_STRUCTURE_BYTES];
    const address = readU64Le(gas[GAS_ADDRESS_OFFSET..][0..8]);
    if (address == 0) return null;
    return .{
        .address_space_id = gas[0],
        .register_bit_width = gas[1],
        .register_bit_offset = gas[2],
        .access_size = gas[3],
        .address = address,
    };
}

fn firmwareSupportsSuspendResume(firmware: FixedAcpiDescription) bool {
    return (firmware.pm1a_control_block != 0 or firmware.pm1b_control_block != 0) and
        firmware.pm1_control_length >= MIN_PM1_CONTROL_LENGTH and
        (firmware.pm1a_event_block != 0 or firmware.pm1b_event_block != 0) and
        firmware.pm_timer_block != 0 and
        firmware.pm_timer_length > 0 and
        firmware.sci_interrupt != 0;
}

pub fn withHardwareSuspendResumeEvidence(
    proof: SuspendResumeProof,
    evidence: HardwareSuspendResumeEvidence,
) SuspendResumeProof {
    var upgraded = proof;
    upgraded.hardware_resume = evidence;
    return upgraded;
}

fn validFadt() [FADT_TEST_TABLE_BYTES]u8 {
    var table = [_]u8{0} ** FADT_TEST_TABLE_BYTES;
    @memcpy(table[0..4], FADT_SIGNATURE);
    writeU32Le(table[4..8], table.len);
    table[FADT_REVISION_OFFSET] = 6;
    @memcpy(table[10..16], "ZIGOS ");
    @memcpy(table[16..24], "NUC11TN ");
    writeU32Le(table[FADT_DSDT_OFFSET..][0..4], 0x00AB_C000);
    writeU16Le(table[FADT_SCI_INTERRUPT_OFFSET..][0..2], 9);
    writeU32Le(table[FADT_PM1A_EVENT_BLOCK_OFFSET..][0..4], 0x1800);
    writeU32Le(table[FADT_PM1A_CONTROL_BLOCK_OFFSET..][0..4], 0x1804);
    writeU32Le(table[FADT_PM_TIMER_BLOCK_OFFSET..][0..4], 0x1808);
    table[FADT_PM1_EVENT_LENGTH_OFFSET] = 4;
    table[FADT_PM1_CONTROL_LENGTH_OFFSET] = MIN_PM1_CONTROL_LENGTH;
    table[FADT_PM_TIMER_LENGTH_OFFSET] = 4;
    table[RESET_REGISTER_OFFSET] = 1;
    table[RESET_REGISTER_OFFSET + 1] = 8;
    table[RESET_REGISTER_OFFSET + 3] = 1;
    writeU64Le(table[RESET_REGISTER_OFFSET + GAS_ADDRESS_OFFSET ..][0..8], 0xCF9);
    table[RESET_VALUE_OFFSET] = 0x06;
    finishChecksum(table[0..], 9, table.len);
    return table;
}

test "FADT parser extracts PM control and reset plumbing" {
    const table = validFadt();
    const parsed = try parseFadt(table[0..]);
    try std.testing.expectEqual(@as(u8, 6), parsed.revision);
    try std.testing.expectEqual(@as(u64, 0x00AB_C000), parsed.dsdt_address);
    try std.testing.expectEqual(@as(u16, 9), parsed.sci_interrupt);
    try std.testing.expectEqual(@as(u32, 0x1804), parsed.pm1a_control_block);
    try std.testing.expectEqual(@as(u8, 2), parsed.pm1_control_length);
    try std.testing.expectEqual(@as(u64, 0xCF9), parsed.reset_register.?.address);
    try std.testing.expectEqual(@as(u8, 0x06), parsed.reset_value);
}

test "FADT suspend resume proof requires PM timer SCI and resumed devices" {
    const table = validFadt();
    const parsed = try parseFadt(table[0..]);
    const proof = try proveSuspendResume(parsed, 5, 100, 140, 5, .{
        .timer = true,
        .framebuffer = true,
        .xhci_input = true,
        .nvme_block = true,
        .i225_network = true,
    });
    try std.testing.expect(proof.verified());
    try std.testing.expect(!proof.productionHardwareVerified());
    try std.testing.expectEqual(@as(u16, 5), proof.cycles);

    const hardware_proof = withHardwareSuspendResumeEvidence(proof, .{
        .source = .hardware_power_transition,
        .pm1_control_sleep_writes = 5,
        .s_state_entry_observations = 5,
        .s0_resume_observations = 5,
        .pm_timer_resume_reads = 10,
        .sci_wake_interrupts = 5,
        .resumed_timer_probes = 5,
        .resumed_framebuffer_probes = 5,
        .resumed_xhci_probes = 5,
        .resumed_nvme_probes = 5,
        .resumed_i225_probes = 5,
    });
    try std.testing.expect(hardware_proof.productionHardwareVerified());

    var missing_sci = hardware_proof;
    missing_sci.hardware_resume.sci_wake_interrupts = 0;
    try std.testing.expect(!missing_sci.productionHardwareVerified());

    try std.testing.expectError(error.SuspendResumeCycleCountInvalid, proveSuspendResume(parsed, 0, 100, 140, 1, proof.resumed));
    try std.testing.expectError(error.PmTimerDidNotAdvance, proveSuspendResume(parsed, 1, 100, 100, 1, proof.resumed));
    try std.testing.expectError(error.WakeInterruptMissing, proveSuspendResume(parsed, 2, 100, 140, 1, proof.resumed));
    try std.testing.expectError(error.ResumeSubsystemMissing, proveSuspendResume(parsed, 1, 100, 140, 1, .{
        .timer = true,
        .framebuffer = true,
        .xhci_input = true,
        .nvme_block = true,
    }));
}

test "FADT parser rejects missing PM control blocks" {
    var table = validFadt();
    writeU32Le(table[FADT_PM1A_CONTROL_BLOCK_OFFSET..][0..4], 0);
    finishChecksum(table[0..], 9, table.len);
    try std.testing.expectError(error.MissingPmControlBlock, parseFadt(table[0..]));
}

test "FADT parser rejects corrupt checksum" {
    var table = validFadt();
    table[FADT_PM1A_CONTROL_BLOCK_OFFSET] +%= 1;
    try std.testing.expectError(error.BadChecksum, parseFadt(table[0..]));
}
