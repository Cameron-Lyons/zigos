//! xHCI capability registers, extended capabilities (supported protocols
//! and USB legacy support) and the firmware-to-OS ownership handoff.

const std = @import("std");
const endian = @import("../../utils/endian.zig");
const spin = @import("../../utils/spin.zig");
const xhci = @import("../xhci.zig");

const readU16Le = endian.readU16Le;
const readU32Le = endian.readU32Le;
const writeU16Le = endian.writeU16Le;
const writeU32Le = endian.writeU32Le;

const CAPABILITY_REGISTERS_BYTES = xhci.CAPABILITY_REGISTERS_BYTES;
const CapabilityRegisters = xhci.CapabilityRegisters;
const ContextSize = xhci.ContextSize;
const DOORBELL_OFFSET_ALIGNMENT_MASK = xhci.DOORBELL_OFFSET_ALIGNMENT_MASK;
const Error = xhci.Error;
const LegacyOwnership = xhci.LegacyOwnership;
const LegacySupport = xhci.LegacySupport;
const MAX_EXTENDED_CAPABILITIES = xhci.MAX_EXTENDED_CAPABILITIES;
const MAX_EXTENDED_CAPABILITY_OFFSET = xhci.MAX_EXTENDED_CAPABILITY_OFFSET;
const PortProtocol = xhci.PortProtocol;
const ProtocolKind = xhci.ProtocolKind;
const RUNTIME_REGISTER_OFFSET_ALIGNMENT_MASK = xhci.RUNTIME_REGISTER_OFFSET_ALIGNMENT_MASK;
const SUPPORTED_PROTOCOLS_SIZE_CEILING_BYTES = xhci.SUPPORTED_PROTOCOLS_SIZE_CEILING_BYTES;
const TEST_CAPABILITY_LENGTH = xhci.TEST_CAPABILITY_LENGTH;
const TEST_CONTEXT_SIZE = xhci.TEST_CONTEXT_SIZE;
const TEST_DOORBELL_OFFSET = xhci.TEST_DOORBELL_OFFSET;
const TEST_INTERFACE_VERSION = xhci.TEST_INTERFACE_VERSION;
const TEST_MAX_DEVICE_SLOTS = xhci.TEST_MAX_DEVICE_SLOTS;
const TEST_MAX_INTERRUPTERS = xhci.TEST_MAX_INTERRUPTERS;
const TEST_MAX_PORTS = xhci.TEST_MAX_PORTS;
const TEST_MAX_SCRATCHPAD_BUFFERS = xhci.TEST_MAX_SCRATCHPAD_BUFFERS;
const TEST_RUNTIME_REGISTER_OFFSET = xhci.TEST_RUNTIME_REGISTER_OFFSET;
const defaultCapabilityRegisters = xhci.defaultCapabilityRegisters;
const endpointZeroMaxPacketSize = xhci.descriptors.endpointZeroMaxPacketSize;

const MIN_CAPABILITY_LENGTH: u8 = 0x20;
const MIN_SUPPORTED_INTERFACE_VERSION: u16 = 0x0110;
const CAPABILITY_LENGTH_OFFSET: usize = 0x00;
const INTERFACE_VERSION_OFFSET: usize = 0x02;
const HCSPARAMS1_OFFSET: usize = 0x04;
const HCSPARAMS2_OFFSET: usize = 0x08;
const HCCPARAMS1_OFFSET: usize = 0x10;
const DOORBELL_OFFSET_OFFSET: usize = 0x14;
const RUNTIME_REGISTER_OFFSET_OFFSET: usize = 0x18;
const U16_REGISTER_BYTES: usize = @sizeOf(u16);
const U32_REGISTER_BYTES: usize = @sizeOf(u32);
const HCSPARAMS1_MAX_INTERRUPTERS_SHIFT = 8;
const HCSPARAMS1_MAX_INTERRUPTERS_MASK: u32 = 0x7FF;
const HCSPARAMS1_MAX_PORTS_SHIFT = 24;
const HCSPARAMS2_MAX_SCRATCHPAD_BUFFERS_HI_SHIFT = 21;
const HCSPARAMS2_MAX_SCRATCHPAD_BUFFERS_LO_SHIFT = 27;
const HCSPARAMS2_MAX_SCRATCHPAD_BUFFERS_PART_MASK: u32 = 0x1F;
const HCSPARAMS2_SCRATCHPAD_RESTORE: u32 = 1 << 26;
const HCCPARAMS1_64_BIT_ADDRESSING: u32 = 1 << 0;
const HCCPARAMS1_CONTEXT_SIZE: u32 = 1 << 2;
const HCCPARAMS1_EXTENDED_CAPABILITY_POINTER_SHIFT = 16;
const EXTENDED_CAPABILITY_ID_MASK: u32 = 0xFF;
const EXTENDED_CAPABILITY_NEXT_POINTER_SHIFT = 8;
const EXTENDED_CAPABILITY_NEXT_POINTER_MASK: u32 = 0xFF;
const EXTENDED_CAPABILITY_DWORD_SHIFT = 2;
const USB_LEGACY_SUPPORT_CAPABILITY_ID: u8 = 1;
const SUPPORTED_PROTOCOL_CAPABILITY_ID: u8 = 2;
const SUPPORTED_PROTOCOL_COMPATIBLE_PORTS_OFFSET: u32 = 0x08;
const SUPPORTED_PROTOCOL_SLOT_TYPE_OFFSET: u32 = 0x0C;
const SUPPORTED_PROTOCOL_SPEED_IDS_OFFSET: u32 = 0x10;
const SUPPORTED_PROTOCOL_USB_NAME_STRING: u32 = 0x2042_5355;
const SUPPORTED_PROTOCOL_MAJOR_REVISION_SHIFT: u5 = 24;
const SUPPORTED_PROTOCOL_MINOR_REVISION_SHIFT: u5 = 16;
const SUPPORTED_PROTOCOL_PORT_COUNT_SHIFT: u5 = 8;
const SUPPORTED_PROTOCOL_SPEED_ID_COUNT_SHIFT: u5 = 28;
const USB_LEGACY_BIOS_OWNED_SEMAPHORE: u32 = 1 << 16;
const USB_LEGACY_OS_OWNED_SEMAPHORE: u32 = 1 << 24;
const TEST_UNSUPPORTED_INTERFACE_VERSION: u16 = 0x0080;
pub const SupportedProtocols = struct {
    first_ports: [MAX_EXTENDED_CAPABILITIES]u8 = @as([MAX_EXTENDED_CAPABILITIES]u8, @splat(0)),
    port_counts: [MAX_EXTENDED_CAPABILITIES]u8 = @as([MAX_EXTENDED_CAPABILITIES]u8, @splat(0)),
    protocol_tags: [MAX_EXTENDED_CAPABILITIES]u8 = @as([MAX_EXTENDED_CAPABILITIES]u8, @splat(0)),
    speed_classes: [MAX_EXTENDED_CAPABILITIES]u32 = @as([MAX_EXTENDED_CAPABILITIES]u32, @splat(0)),
    range_count: u8 = 0,

    pub fn forPort(self: *const SupportedProtocols, port_id: u8) ?PortProtocol {
        if (port_id == 0) return null;
        for (0..self.range_count) |index| {
            if (rangeContains(self.first_ports[index], self.port_counts[index], port_id)) {
                return decodeProtocol(self.protocol_tags[index], self.speed_classes[index]);
            }
        }
        return null;
    }

    fn append(
        self: *SupportedProtocols,
        first_port: u8,
        port_count: u8,
        protocol: PortProtocol,
    ) Error!void {
        for (0..self.range_count) |index| {
            if (rangesOverlap(
                self.first_ports[index],
                self.port_counts[index],
                first_port,
                port_count,
            )) {
                return error.OverlappingSupportedProtocolPorts;
            }
        }
        if (self.range_count == MAX_EXTENDED_CAPABILITIES) {
            return error.ExtendedCapabilityTraversalLimit;
        }
        const index = self.range_count;
        self.first_ports[index] = first_port;
        self.port_counts[index] = port_count;
        const kind_tag: u8 = switch (protocol.kind) {
            .usb2 => 0,
            .usb3 => 1,
        };
        self.protocol_tags[index] = kind_tag | (@as(u8, protocol.slot_type) << 1);
        self.speed_classes[index] = encodeSpeedClasses(protocol);
        self.range_count += 1;
    }

    fn rangeContains(first_port: u8, port_count: u8, port_id: u8) bool {
        const port = @as(u16, port_id);
        const first = @as(u16, first_port);
        return port >= first and port < first + port_count;
    }

    fn rangesOverlap(
        first_port: u8,
        port_count: u8,
        other_first_port: u8,
        other_port_count: u8,
    ) bool {
        const first = @as(u16, first_port);
        const end = first + port_count;
        const other_first = @as(u16, other_first_port);
        const other_end = other_first + other_port_count;
        return first < other_end and other_first < end;
    }

    fn encodeSpeedClasses(protocol: PortProtocol) u32 {
        return switch (protocol.kind) {
            .usb2 => {
                const low_plane = protocol.low_speed_ids | protocol.high_speed_ids;
                const high_plane = protocol.full_speed_ids | protocol.high_speed_ids;
                return @as(u32, low_plane) | (@as(u32, high_plane) << 16);
            },
            .usb3 => protocol.speed_ids,
        };
    }

    fn decodeProtocol(tag: u8, speed_classes: u32) PortProtocol {
        const kind: ProtocolKind = if ((tag & 1) == 0) .usb2 else .usb3;
        const slot_type: u5 = @truncate(tag >> 1);
        if (kind == .usb3) {
            return .{
                .kind = kind,
                .slot_type = slot_type,
                .speed_ids = @truncate(speed_classes),
            };
        }
        const low_plane: u16 = @truncate(speed_classes);
        const high_plane: u16 = @truncate(speed_classes >> 16);
        return .{
            .kind = kind,
            .slot_type = slot_type,
            .speed_ids = low_plane | high_plane,
            .low_speed_ids = low_plane & ~high_plane,
            .full_speed_ids = ~low_plane & high_plane,
            .high_speed_ids = low_plane & high_plane,
        };
    }
};

comptime {
    if (@sizeOf(SupportedProtocols) > SUPPORTED_PROTOCOLS_SIZE_CEILING_BYTES) {
        @compileError("xHCI supported-protocol metadata exceeds its compact size ceiling");
    }
}

// Keep caller-owned output unchanged until every capability is admitted.
pub fn parseCapabilityRegistersInto(out: *CapabilityRegisters, mmio: []const u8) Error!void {
    if (mmio.len < CAPABILITY_REGISTERS_BYTES) return error.TooSmall;
    const capability_length = mmio[CAPABILITY_LENGTH_OFFSET];
    if (capability_length < MIN_CAPABILITY_LENGTH or
        (capability_length & (@sizeOf(u32) - 1)) != 0)
    {
        return error.InvalidCapabilityLength;
    }

    const interface_version = readU16Le(mmio[INTERFACE_VERSION_OFFSET .. INTERFACE_VERSION_OFFSET + U16_REGISTER_BYTES]);
    if (interface_version < MIN_SUPPORTED_INTERFACE_VERSION) return error.UnsupportedVersion;

    const hcsparams1 = readU32Le(mmio[HCSPARAMS1_OFFSET .. HCSPARAMS1_OFFSET + U32_REGISTER_BYTES]);
    const max_device_slots: u8 = @truncate(hcsparams1);
    const max_interrupters: u16 = @intCast(
        (hcsparams1 >> HCSPARAMS1_MAX_INTERRUPTERS_SHIFT) & HCSPARAMS1_MAX_INTERRUPTERS_MASK,
    );
    const max_ports: u8 = @truncate(hcsparams1 >> HCSPARAMS1_MAX_PORTS_SHIFT);
    if (max_device_slots == 0) return error.MissingDeviceSlots;
    if (max_ports == 0) return error.MissingPorts;
    if (max_interrupters == 0) return error.MissingInterrupters;

    const hcsparams2 = readU32Le(mmio[HCSPARAMS2_OFFSET .. HCSPARAMS2_OFFSET + U32_REGISTER_BYTES]);
    const scratchpad_hi: u16 = @intCast(
        (hcsparams2 >> HCSPARAMS2_MAX_SCRATCHPAD_BUFFERS_HI_SHIFT) &
            HCSPARAMS2_MAX_SCRATCHPAD_BUFFERS_PART_MASK,
    );
    const scratchpad_lo: u16 = @intCast(
        (hcsparams2 >> HCSPARAMS2_MAX_SCRATCHPAD_BUFFERS_LO_SHIFT) &
            HCSPARAMS2_MAX_SCRATCHPAD_BUFFERS_PART_MASK,
    );
    const max_scratchpad_buffers = (scratchpad_hi << 5) | scratchpad_lo;
    const scratchpad_restore = (hcsparams2 & HCSPARAMS2_SCRATCHPAD_RESTORE) != 0;
    if (max_scratchpad_buffers == 0 and scratchpad_restore) return error.InvalidScratchpadRestore;

    const hccparams1 = readU32Le(mmio[HCCPARAMS1_OFFSET .. HCCPARAMS1_OFFSET + U32_REGISTER_BYTES]);
    const supports_64_bit_addressing = (hccparams1 & HCCPARAMS1_64_BIT_ADDRESSING) != 0;
    if (!supports_64_bit_addressing) return error.Unsupported32BitAddressing;
    const context_size: ContextSize = if ((hccparams1 & HCCPARAMS1_CONTEXT_SIZE) != 0)
        .bytes_64
    else
        .bytes_32;
    const extended_capability_offset =
        (hccparams1 >> HCCPARAMS1_EXTENDED_CAPABILITY_POINTER_SHIFT) << EXTENDED_CAPABILITY_DWORD_SHIFT;

    const doorbell_offset = readU32Le(mmio[DOORBELL_OFFSET_OFFSET .. DOORBELL_OFFSET_OFFSET + U32_REGISTER_BYTES]);
    if (doorbell_offset == 0) return error.MissingDoorbellRegisters;
    if ((doorbell_offset & DOORBELL_OFFSET_ALIGNMENT_MASK) != 0) return error.InvalidDoorbellOffset;
    const runtime_register_offset = readU32Le(mmio[RUNTIME_REGISTER_OFFSET_OFFSET .. RUNTIME_REGISTER_OFFSET_OFFSET + U32_REGISTER_BYTES]);
    if (runtime_register_offset == 0) return error.MissingRuntimeRegisters;
    if ((runtime_register_offset & RUNTIME_REGISTER_OFFSET_ALIGNMENT_MASK) != 0) {
        return error.InvalidRuntimeRegisterOffset;
    }

    out.* = .{
        .capability_length = capability_length,
        .interface_version = interface_version,
        .max_device_slots = max_device_slots,
        .max_interrupters = max_interrupters,
        .max_ports = max_ports,
        .supports_64_bit_addressing = supports_64_bit_addressing,
        .context_size = context_size,
        .max_scratchpad_buffers = max_scratchpad_buffers,
        .scratchpad_restore = scratchpad_restore,
        .extended_capability_offset = extended_capability_offset,
        .doorbell_offset = doorbell_offset,
        .runtime_register_offset = runtime_register_offset,
    };
}

pub fn findLegacySupport(first_offset: u32, reader: anytype) Error!?LegacySupport {
    if (first_offset == 0) return null;
    if ((first_offset & (@sizeOf(u32) - 1)) != 0 or first_offset > MAX_EXTENDED_CAPABILITY_OFFSET) {
        return error.ExtendedCapabilityOutOfRange;
    }

    var offset = first_offset;
    var visited: usize = 0;
    while (visited < MAX_EXTENDED_CAPABILITIES) : (visited += 1) {
        const header = reader.readDword(offset);
        const capability_id: u8 = @truncate(header & EXTENDED_CAPABILITY_ID_MASK);
        if (capability_id == USB_LEGACY_SUPPORT_CAPABILITY_ID) {
            return .{
                .offset = offset,
                .firmware_owned = firmwareOwned(header),
                .os_owned = osOwned(header),
            };
        }

        const next_dwords = (header >> EXTENDED_CAPABILITY_NEXT_POINTER_SHIFT) &
            EXTENDED_CAPABILITY_NEXT_POINTER_MASK;
        if (next_dwords == 0) return null;
        const delta = next_dwords << EXTENDED_CAPABILITY_DWORD_SHIFT;
        if (offset > MAX_EXTENDED_CAPABILITY_OFFSET - delta) {
            return error.ExtendedCapabilityOutOfRange;
        }
        offset += delta;
    }
    return error.ExtendedCapabilityTraversalLimit;
}

// Parse directly into unpublished storage. Clear failures so an admitted
// prefix of a malformed capability chain can never become a usable result.
pub fn parseSupportedProtocolsInto(
    protocols: *SupportedProtocols,
    capabilities: CapabilityRegisters,
    first_offset: u32,
    reader: anytype,
) Error!void {
    @memset(std.mem.asBytes(protocols), 0);
    errdefer @memset(std.mem.asBytes(protocols), 0);
    if (first_offset == 0) return error.MissingSupportedProtocols;
    if ((first_offset & (@sizeOf(u32) - 1)) != 0 or first_offset > MAX_EXTENDED_CAPABILITY_OFFSET) {
        return error.ExtendedCapabilityOutOfRange;
    }

    var terminal = false;
    var offset = first_offset;
    var visited: usize = 0;
    while (visited < MAX_EXTENDED_CAPABILITIES) : (visited += 1) {
        const header = reader.readDword(offset);
        const capability_id: u8 = @truncate(header & EXTENDED_CAPABILITY_ID_MASK);
        var minimum_next_dwords: u32 = 1;
        if (capability_id == SUPPORTED_PROTOCOL_CAPABILITY_ID) {
            const extent_end = @as(u64, offset) + SUPPORTED_PROTOCOL_SLOT_TYPE_OFFSET +
                @sizeOf(u32);
            if (extent_end > @as(u64, MAX_EXTENDED_CAPABILITY_OFFSET) + @sizeOf(u32)) {
                return error.ExtendedCapabilityOutOfRange;
            }
            if (reader.readDword(offset + @sizeOf(u32)) != SUPPORTED_PROTOCOL_USB_NAME_STRING) {
                return error.InvalidSupportedProtocol;
            }
            const major_revision: u8 = @truncate(header >> SUPPORTED_PROTOCOL_MAJOR_REVISION_SHIFT);
            const minor_revision: u8 = @truncate(header >> SUPPORTED_PROTOCOL_MINOR_REVISION_SHIFT);
            const kind: ProtocolKind = switch (major_revision) {
                2 => if (minor_revision == 0) .usb2 else return error.InvalidSupportedProtocol,
                3 => switch (minor_revision) {
                    0x00, 0x10, 0x20 => .usb3,
                    else => return error.InvalidSupportedProtocol,
                },
                else => return error.InvalidSupportedProtocol,
            };
            const compatible_ports = reader.readDword(
                offset + SUPPORTED_PROTOCOL_COMPATIBLE_PORTS_OFFSET,
            );
            const first_port: u8 = @truncate(compatible_ports);
            const port_count: u8 = @truncate(
                compatible_ports >> SUPPORTED_PROTOCOL_PORT_COUNT_SHIFT,
            );
            const speed_id_count: u8 = @truncate(
                compatible_ports >> SUPPORTED_PROTOCOL_SPEED_ID_COUNT_SHIFT,
            );
            const capability_end = @as(u64, offset) +
                SUPPORTED_PROTOCOL_SLOT_TYPE_OFFSET + @sizeOf(u32) +
                @as(u64, speed_id_count) * @sizeOf(u32);
            if (capability_end > @as(u64, MAX_EXTENDED_CAPABILITY_OFFSET) + @sizeOf(u32)) {
                return error.ExtendedCapabilityOutOfRange;
            }
            minimum_next_dwords = 4 + speed_id_count;
            if (first_port == 0 or port_count == 0 or
                @as(u16, first_port) + @as(u16, port_count) - 1 > capabilities.max_ports)
            {
                return error.InvalidSupportedProtocol;
            }
            const slot_type: u5 = @truncate(reader.readDword(
                offset + SUPPORTED_PROTOCOL_SLOT_TYPE_OFFSET,
            ));
            var speed_ids: u16 = 0;
            var low_speed_ids: u16 = 0;
            var full_speed_ids: u16 = 0;
            var high_speed_ids: u16 = 0;
            if (speed_id_count == 0) {
                switch (kind) {
                    .usb2 => {
                        speed_ids = (@as(u16, 1) << 1) |
                            (@as(u16, 1) << 2) |
                            (@as(u16, 1) << 3);
                        full_speed_ids = @as(u16, 1) << 1;
                        low_speed_ids = @as(u16, 1) << 2;
                        high_speed_ids = @as(u16, 1) << 3;
                    },
                    .usb3 => {
                        const highest_speed_id: u4 = switch (minor_revision) {
                            0x00 => 4,
                            0x10 => 5,
                            0x20 => 7,
                            else => unreachable,
                        };
                        var speed_id: u4 = 4;
                        while (speed_id <= highest_speed_id) : (speed_id += 1) {
                            speed_ids |= @as(u16, 1) << speed_id;
                        }
                    },
                }
            } else {
                var pending_asymmetric_rx: ?u4 = null;
                var speed_index: u8 = 0;
                while (speed_index < speed_id_count) : (speed_index += 1) {
                    const psi = reader.readDword(
                        offset + SUPPORTED_PROTOCOL_SPEED_IDS_OFFSET +
                            @as(u32, speed_index) * @sizeOf(u32),
                    );
                    const speed_id: u4 = @truncate(psi);
                    const exponent: u2 = @truncate(psi >> 4);
                    const psi_type: u2 = @truncate(psi >> 6);
                    const link_protocol: u2 = @truncate(psi >> 14);
                    const mantissa: u16 = @truncate(psi >> 16);
                    if (speed_id == 0 or mantissa == 0 or
                        (kind == .usb2 and link_protocol != 0))
                    {
                        return error.InvalidSupportedProtocol;
                    }
                    const speed_bit = @as(u16, 1) << speed_id;
                    switch (psi_type) {
                        0 => {
                            if (pending_asymmetric_rx != null or (speed_ids & speed_bit) != 0) {
                                return error.InvalidSupportedProtocol;
                            }
                        },
                        2 => {
                            if (pending_asymmetric_rx != null or (speed_ids & speed_bit) != 0) {
                                return error.InvalidSupportedProtocol;
                            }
                            pending_asymmetric_rx = speed_id;
                        },
                        3 => {
                            if (pending_asymmetric_rx == null or pending_asymmetric_rx.? != speed_id) {
                                return error.InvalidSupportedProtocol;
                            }
                            pending_asymmetric_rx = null;
                        },
                        else => return error.InvalidSupportedProtocol,
                    }
                    speed_ids |= speed_bit;
                    const scale = ([_]u64{ 1, 1_000, 1_000_000, 1_000_000_000 })[exponent];
                    const bits_per_second = @as(u64, mantissa) * scale;
                    if (kind == .usb2) {
                        const classified = low_speed_ids | full_speed_ids | high_speed_ids;
                        const speed_class: enum { low, full, high } =
                            if (bits_per_second <= 1_500_000)
                                .low
                            else if (bits_per_second >= 480_000_000)
                                .high
                            else
                                .full;
                        if ((classified & speed_bit) != 0) {
                            const same_class = switch (speed_class) {
                                .low => (low_speed_ids & speed_bit) != 0,
                                .full => (full_speed_ids & speed_bit) != 0,
                                .high => (high_speed_ids & speed_bit) != 0,
                            };
                            if (!same_class) return error.InvalidSupportedProtocol;
                        }
                        switch (speed_class) {
                            .low => low_speed_ids |= speed_bit,
                            .full => full_speed_ids |= speed_bit,
                            .high => high_speed_ids |= speed_bit,
                        }
                    }
                }
                if (pending_asymmetric_rx != null) return error.InvalidSupportedProtocol;
            }
            try protocols.append(first_port, port_count, .{
                .kind = kind,
                .slot_type = slot_type,
                .speed_ids = speed_ids,
                .low_speed_ids = low_speed_ids,
                .full_speed_ids = full_speed_ids,
                .high_speed_ids = high_speed_ids,
            });
        }

        const next_dwords = (header >> EXTENDED_CAPABILITY_NEXT_POINTER_SHIFT) &
            EXTENDED_CAPABILITY_NEXT_POINTER_MASK;
        if (next_dwords == 0) {
            terminal = true;
            break;
        }
        if (next_dwords < minimum_next_dwords) return error.InvalidSupportedProtocol;
        const delta = next_dwords << EXTENDED_CAPABILITY_DWORD_SHIFT;
        if (offset > MAX_EXTENDED_CAPABILITY_OFFSET - delta) {
            return error.ExtendedCapabilityOutOfRange;
        }
        offset += delta;
    }
    if (!terminal) return error.ExtendedCapabilityTraversalLimit;
    if (protocols.range_count == 0) return error.MissingSupportedProtocols;
}

pub fn claimLegacyOwnership(
    legacy: LegacySupport,
    reader: anytype,
    deadline: anytype,
) Error!LegacyOwnership {
    if (!legacy.os_owned) reader.writeOsOwnedByte(legacy.offset, 1);

    while (true) {
        const header = reader.readDword(legacy.offset);
        const capability_id: u8 = @truncate(header & EXTENDED_CAPABILITY_ID_MASK);
        if (capability_id != USB_LEGACY_SUPPORT_CAPABILITY_ID) {
            return error.LegacyCapabilityChanged;
        }
        if (!osOwned(header)) return error.OwnershipRequestRejected;
        if (!firmwareOwned(header)) return .os_owned;
        if (deadline.expired()) return error.FirmwareOwnershipTimeout;
        spin.hint();
    }
}

fn firmwareOwned(header: u32) bool {
    return (header & USB_LEGACY_BIOS_OWNED_SEMAPHORE) != 0;
}

fn osOwned(header: u32) bool {
    return (header & USB_LEGACY_OS_OWNED_SEMAPHORE) != 0;
}

fn validCapabilityRegisters() [CAPABILITY_REGISTERS_BYTES]u8 {
    var mmio = @as([CAPABILITY_REGISTERS_BYTES]u8, @splat(0));
    mmio[CAPABILITY_LENGTH_OFFSET] = TEST_CAPABILITY_LENGTH;
    writeU16Le(mmio[INTERFACE_VERSION_OFFSET .. INTERFACE_VERSION_OFFSET + U16_REGISTER_BYTES], TEST_INTERFACE_VERSION);
    writeU32Le(
        mmio[HCSPARAMS1_OFFSET .. HCSPARAMS1_OFFSET + U32_REGISTER_BYTES],
        @as(u32, TEST_MAX_DEVICE_SLOTS) |
            (@as(u32, TEST_MAX_INTERRUPTERS) << HCSPARAMS1_MAX_INTERRUPTERS_SHIFT) |
            (@as(u32, TEST_MAX_PORTS) << HCSPARAMS1_MAX_PORTS_SHIFT),
    );
    writeU32Le(
        mmio[HCSPARAMS2_OFFSET .. HCSPARAMS2_OFFSET + U32_REGISTER_BYTES],
        (@as(u32, TEST_MAX_SCRATCHPAD_BUFFERS >> 5) << HCSPARAMS2_MAX_SCRATCHPAD_BUFFERS_HI_SHIFT) |
            ((@as(u32, TEST_MAX_SCRATCHPAD_BUFFERS) & HCSPARAMS2_MAX_SCRATCHPAD_BUFFERS_PART_MASK) << HCSPARAMS2_MAX_SCRATCHPAD_BUFFERS_LO_SHIFT) |
            HCSPARAMS2_SCRATCHPAD_RESTORE,
    );
    writeU32Le(
        mmio[HCCPARAMS1_OFFSET .. HCCPARAMS1_OFFSET + U32_REGISTER_BYTES],
        HCCPARAMS1_64_BIT_ADDRESSING | HCCPARAMS1_CONTEXT_SIZE,
    );
    writeU32Le(mmio[DOORBELL_OFFSET_OFFSET .. DOORBELL_OFFSET_OFFSET + U32_REGISTER_BYTES], TEST_DOORBELL_OFFSET);
    writeU32Le(mmio[RUNTIME_REGISTER_OFFSET_OFFSET .. RUNTIME_REGISTER_OFFSET_OFFSET + U32_REGISTER_BYTES], TEST_RUNTIME_REGISTER_OFFSET);
    return mmio;
}

test "xHCI in-place capability parsing preserves output until full admission" {
    var out = defaultCapabilityRegisters();
    out.max_ports = 42;
    const original = out;
    var mmio = validCapabilityRegisters();
    try std.testing.expectError(error.TooSmall, parseCapabilityRegistersInto(&out, mmio[0..1]));
    try std.testing.expectEqualDeep(original, out);
    writeU32Le(mmio[RUNTIME_REGISTER_OFFSET_OFFSET..][0..4], TEST_RUNTIME_REGISTER_OFFSET | 1);
    try std.testing.expectError(error.InvalidRuntimeRegisterOffset, parseCapabilityRegistersInto(&out, &mmio));
    try std.testing.expectEqualDeep(original, out);
    mmio = validCapabilityRegisters();
    try parseCapabilityRegistersInto(&out, &mmio);
    try std.testing.expectEqual(TEST_MAX_PORTS, out.max_ports);
    try std.testing.expectEqual(TEST_RUNTIME_REGISTER_OFFSET, out.runtime_register_offset);
}

test "xHCI capability parser extracts controller limits" {
    const mmio = validCapabilityRegisters();
    const caps = try testing.parseCapabilityRegisters(mmio[0..]);
    try std.testing.expectEqual(TEST_CAPABILITY_LENGTH, caps.capability_length);
    try std.testing.expectEqual(TEST_INTERFACE_VERSION, caps.interface_version);
    try std.testing.expectEqual(TEST_MAX_DEVICE_SLOTS, caps.max_device_slots);
    try std.testing.expectEqual(TEST_MAX_INTERRUPTERS, caps.max_interrupters);
    try std.testing.expectEqual(TEST_MAX_PORTS, caps.max_ports);
    try std.testing.expect(caps.supports_64_bit_addressing);
    try std.testing.expectEqual(TEST_CONTEXT_SIZE, caps.context_size);
    try std.testing.expectEqual(TEST_MAX_SCRATCHPAD_BUFFERS, caps.max_scratchpad_buffers);
    try std.testing.expect(caps.scratchpad_restore);
    try std.testing.expectEqual(@as(u32, 0), caps.extended_capability_offset);
    try std.testing.expectEqual(TEST_DOORBELL_OFFSET, caps.doorbell_offset);
    try std.testing.expectEqual(TEST_RUNTIME_REGISTER_OFFSET, caps.runtime_register_offset);
}

test "xHCI capability parser isolates context scratchpad and interrupter fields" {
    var mmio = validCapabilityRegisters();
    writeU32Le(
        mmio[HCSPARAMS1_OFFSET .. HCSPARAMS1_OFFSET + U32_REGISTER_BYTES],
        @as(u32, TEST_MAX_DEVICE_SLOTS) |
            (@as(u32, TEST_MAX_INTERRUPTERS) << HCSPARAMS1_MAX_INTERRUPTERS_SHIFT) |
            (@as(u32, 0x1F) << 19) |
            (@as(u32, TEST_MAX_PORTS) << HCSPARAMS1_MAX_PORTS_SHIFT),
    );
    writeU32Le(
        mmio[HCSPARAMS2_OFFSET .. HCSPARAMS2_OFFSET + U32_REGISTER_BYTES],
        (HCSPARAMS2_MAX_SCRATCHPAD_BUFFERS_PART_MASK << HCSPARAMS2_MAX_SCRATCHPAD_BUFFERS_HI_SHIFT) |
            (HCSPARAMS2_MAX_SCRATCHPAD_BUFFERS_PART_MASK << HCSPARAMS2_MAX_SCRATCHPAD_BUFFERS_LO_SHIFT),
    );
    writeU32Le(
        mmio[HCCPARAMS1_OFFSET .. HCCPARAMS1_OFFSET + U32_REGISTER_BYTES],
        HCCPARAMS1_64_BIT_ADDRESSING,
    );

    const caps = try testing.parseCapabilityRegisters(mmio[0..]);
    try std.testing.expectEqual(TEST_MAX_INTERRUPTERS, caps.max_interrupters);
    try std.testing.expectEqual(ContextSize.bytes_32, caps.context_size);
    try std.testing.expectEqual(@as(u16, 1023), caps.max_scratchpad_buffers);
    try std.testing.expect(!caps.scratchpad_restore);
}

const TestExtendedCapabilityReader = struct {
    bytes: []const u8,

    fn readDword(self: @This(), offset: u32) u32 {
        const start: usize = @intCast(offset);
        return readU32Le(self.bytes[start .. start + @sizeOf(u32)]);
    }
};

const EndlessExtendedCapabilityReader = struct {
    fn readDword(_: @This(), _: u32) u32 {
        return @as(u32, 0x7F) | (@as(u32, 1) << EXTENDED_CAPABILITY_NEXT_POINTER_SHIFT);
    }
};

test "xHCI capability parser extracts the extended capability pointer" {
    var mmio = validCapabilityRegisters();
    writeU32Le(
        mmio[HCCPARAMS1_OFFSET .. HCCPARAMS1_OFFSET + U32_REGISTER_BYTES],
        HCCPARAMS1_64_BIT_ADDRESSING |
            HCCPARAMS1_CONTEXT_SIZE |
            (@as(u32, 0x2000) << HCCPARAMS1_EXTENDED_CAPABILITY_POINTER_SHIFT),
    );
    const caps = try testing.parseCapabilityRegisters(mmio[0..]);
    try std.testing.expectEqual(@as(u32, 0x8000), caps.extended_capability_offset);
}

test "xHCI legacy ownership accepts absent and firmware-released capabilities" {
    var registers = @as([0x80]u8, @splat(0));
    var reader = TestExtendedCapabilityReader{ .bytes = &registers };
    try std.testing.expectEqual(LegacyOwnership.not_present, try testing.inspectLegacyOwnership(0, reader));

    writeU32Le(registers[0x40..0x44], @as(u32, 0x7F) | (@as(u32, 4) << EXTENDED_CAPABILITY_NEXT_POINTER_SHIFT));
    writeU32Le(registers[0x50..0x54], USB_LEGACY_SUPPORT_CAPABILITY_ID);
    reader = .{ .bytes = &registers };
    try std.testing.expectEqual(LegacyOwnership.firmware_released, try testing.inspectLegacyOwnership(0x40, reader));

    writeU32Le(registers[0x50..0x54], USB_LEGACY_SUPPORT_CAPABILITY_ID | USB_LEGACY_OS_OWNED_SEMAPHORE);
    reader = .{ .bytes = &registers };
    try std.testing.expectEqual(LegacyOwnership.os_owned, try testing.inspectLegacyOwnership(0x40, reader));
}

test "xHCI supported protocols accept sparse nonoverlapping USB port ranges" {
    var registers = @as([0x100]u8, @splat(0));
    writeU32Le(
        registers[0x40..0x44],
        SUPPORTED_PROTOCOL_CAPABILITY_ID |
            (@as(u32, 4) << EXTENDED_CAPABILITY_NEXT_POINTER_SHIFT) |
            (@as(u32, 2) << SUPPORTED_PROTOCOL_MAJOR_REVISION_SHIFT),
    );
    writeU32Le(registers[0x44..0x48], SUPPORTED_PROTOCOL_USB_NAME_STRING);
    writeU32Le(registers[0x48..0x4C], 1 | (@as(u32, 6) << 8));
    writeU32Le(registers[0x4C..0x50], 0);
    writeU32Le(
        registers[0x50..0x54],
        SUPPORTED_PROTOCOL_CAPABILITY_ID |
            (@as(u32, 3) << SUPPORTED_PROTOCOL_MAJOR_REVISION_SHIFT),
    );
    writeU32Le(registers[0x54..0x58], SUPPORTED_PROTOCOL_USB_NAME_STRING);
    writeU32Le(registers[0x58..0x5C], 7 | (@as(u32, 6) << 8));
    writeU32Le(registers[0x5C..0x60], 1);

    var capabilities = defaultCapabilityRegisters();
    capabilities.max_ports = 12;
    const reader = TestExtendedCapabilityReader{ .bytes = &registers };
    const protocols = try testing.parseSupportedProtocols(capabilities, 0x40, reader);
    try std.testing.expectEqual(@as(usize, 452), @sizeOf(SupportedProtocols));
    try std.testing.expectEqual(@as(u8, 2), protocols.range_count);
    try std.testing.expectEqual(ProtocolKind.usb2, protocols.forPort(1).?.kind);
    try std.testing.expectEqual(@as(u5, 0), protocols.forPort(6).?.slot_type);
    try std.testing.expectEqual(@as(u16, 64), try endpointZeroMaxPacketSize(protocols.forPort(1).?, 3));
    try std.testing.expectEqual(@as(u16, 8), try endpointZeroMaxPacketSize(protocols.forPort(1).?, 1));
    try std.testing.expectEqual(@as(u16, 1) << 1, protocols.forPort(1).?.full_speed_ids);
    try std.testing.expectEqual(@as(u16, 1) << 2, protocols.forPort(1).?.low_speed_ids);
    try std.testing.expectEqual(ProtocolKind.usb3, protocols.forPort(7).?.kind);
    try std.testing.expectEqual(@as(u5, 1), protocols.forPort(12).?.slot_type);
    try std.testing.expectEqual(@as(u16, 512), try endpointZeroMaxPacketSize(protocols.forPort(7).?, 4));
    try std.testing.expectError(
        error.InvalidProtocolSpeed,
        endpointZeroMaxPacketSize(protocols.forPort(7).?, 3),
    );
    try std.testing.expect(protocols.forPort(0) == null);

    var full_range = SupportedProtocols{};
    try full_range.append(1, std.math.maxInt(u8), .{ .kind = .usb3, .slot_type = 1 });
    try std.testing.expectEqual(ProtocolKind.usb3, full_range.forPort(std.math.maxInt(u8)).?.kind);

    writeU32Le(registers[0x58..0x5C], 6 | (@as(u32, 6) << 8));
    try std.testing.expectError(
        error.OverlappingSupportedProtocolPorts,
        testing.parseSupportedProtocols(capabilities, 0x40, reader),
    );
    var in_place = protocols;
    try std.testing.expectError(
        error.OverlappingSupportedProtocolPorts,
        parseSupportedProtocolsInto(&in_place, capabilities, 0x40, reader),
    );
    try std.testing.expectEqual(@as(u8, 0), in_place.range_count);
    try std.testing.expect(in_place.forPort(1) == null);
    try std.testing.expect(in_place.forPort(6) == null);
    for (std.mem.asBytes(&in_place)) |byte| try std.testing.expectEqual(@as(u8, 0), byte);
    writeU32Le(registers[0x58..0x5C], 8 | (@as(u32, 5) << 8));
    const sparse = try testing.parseSupportedProtocols(capabilities, 0x40, reader);
    try std.testing.expect(sparse.forPort(7) == null);
    try std.testing.expectEqual(ProtocolKind.usb3, sparse.forPort(8).?.kind);
    try parseSupportedProtocolsInto(&in_place, capabilities, 0x40, reader);
    try std.testing.expectEqualDeep(sparse, in_place);
    try std.testing.expectError(error.MissingSupportedProtocols, parseSupportedProtocolsInto(&in_place, capabilities, 0, reader));
    try std.testing.expect(in_place.forPort(8) == null);

    writeU32Le(registers[0x44..0x48], 0);
    try std.testing.expectError(
        error.InvalidSupportedProtocol,
        testing.parseSupportedProtocols(capabilities, 0x40, reader),
    );
    writeU32Le(registers[0x44..0x48], SUPPORTED_PROTOCOL_USB_NAME_STRING);
    writeU32Le(
        registers[0x40..0x44],
        SUPPORTED_PROTOCOL_CAPABILITY_ID |
            (@as(u32, 4) << EXTENDED_CAPABILITY_NEXT_POINTER_SHIFT) |
            (@as(u32, 1) << SUPPORTED_PROTOCOL_MINOR_REVISION_SHIFT) |
            (@as(u32, 2) << SUPPORTED_PROTOCOL_MAJOR_REVISION_SHIFT),
    );
    try std.testing.expectError(
        error.InvalidSupportedProtocol,
        testing.parseSupportedProtocols(capabilities, 0x40, reader),
    );
}

test "xHCI supported protocol PSI definitions validate custom USB2 speed ids" {
    var registers = @as([0x80]u8, @splat(0));
    writeU32Le(
        registers[0x40..0x44],
        SUPPORTED_PROTOCOL_CAPABILITY_ID |
            (@as(u32, 2) << SUPPORTED_PROTOCOL_MAJOR_REVISION_SHIFT),
    );
    writeU32Le(registers[0x44..0x48], SUPPORTED_PROTOCOL_USB_NAME_STRING);
    writeU32Le(
        registers[0x48..0x4C],
        1 | (@as(u32, 1) << 8) | (@as(u32, 2) << 28),
    );
    writeU32Le(registers[0x4C..0x50], 5);
    writeU32Le(
        registers[0x50..0x54],
        9 | (@as(u32, 2) << 4) | (@as(u32, 12) << 16),
    );
    writeU32Le(
        registers[0x54..0x58],
        10 | (@as(u32, 2) << 4) | (@as(u32, 480) << 16),
    );
    var capabilities = defaultCapabilityRegisters();
    capabilities.max_ports = 1;
    const reader = TestExtendedCapabilityReader{ .bytes = &registers };
    const protocols = try testing.parseSupportedProtocols(capabilities, 0x40, reader);
    const protocol = protocols.forPort(1).?;
    try std.testing.expectEqual(@as(u5, 5), protocol.slot_type);
    try std.testing.expectEqual(@as(u16, 8), try endpointZeroMaxPacketSize(protocol, 9));
    try std.testing.expectEqual(@as(u16, 64), try endpointZeroMaxPacketSize(protocol, 10));
    try std.testing.expectEqual(@as(u16, 1) << 9, protocol.full_speed_ids);
    try std.testing.expectEqual(@as(u16, 1) << 10, protocol.high_speed_ids);

    writeU32Le(
        registers[0x54..0x58],
        9 | (@as(u32, 2) << 4) | (@as(u32, 480) << 16),
    );
    try std.testing.expectError(
        error.InvalidSupportedProtocol,
        testing.parseSupportedProtocols(capabilities, 0x40, reader),
    );
}

test "xHCI legacy ownership rejects firmware-owned and malformed chains" {
    var registers = @as([0x80]u8, @splat(0));
    writeU32Le(
        registers[0x40..0x44],
        USB_LEGACY_SUPPORT_CAPABILITY_ID | USB_LEGACY_BIOS_OWNED_SEMAPHORE,
    );
    const reader = TestExtendedCapabilityReader{ .bytes = &registers };
    try std.testing.expectError(error.FirmwareOwnsController, testing.inspectLegacyOwnership(0x40, reader));

    const terminal_reader = EndlessExtendedCapabilityReader{};
    try std.testing.expectError(
        error.ExtendedCapabilityOutOfRange,
        testing.inspectLegacyOwnership(MAX_EXTENDED_CAPABILITY_OFFSET, terminal_reader),
    );
    try std.testing.expectError(
        error.ExtendedCapabilityTraversalLimit,
        testing.inspectLegacyOwnership(0x40, terminal_reader),
    );
}

const MockOwnershipReader = struct {
    header: u32,
    release_after_reads: ?usize = null,
    accept_os_write: bool = true,
    read_count: usize = 0,
    os_write_count: usize = 0,
    last_write_offset: u32 = 0,
    last_write_value: u8 = 0,

    pub fn readDword(self: *@This(), _: u32) u32 {
        self.read_count += 1;
        if (self.os_write_count != 0) {
            if (self.release_after_reads) |release_after| {
                if (self.read_count >= release_after) self.header &= ~USB_LEGACY_BIOS_OWNED_SEMAPHORE;
            }
        }
        return self.header;
    }

    pub fn writeOsOwnedByte(self: *@This(), offset: u32, value: u8) void {
        self.os_write_count += 1;
        self.last_write_offset = offset;
        self.last_write_value = value;
        if (self.accept_os_write and value == 1) self.header |= USB_LEGACY_OS_OWNED_SEMAPHORE;
    }
};

const MockOwnershipDeadline = struct {
    remaining_checks: usize,

    pub fn expired(self: *@This()) bool {
        if (self.remaining_checks == 0) return true;
        self.remaining_checks -= 1;
        return false;
    }
};

test "xHCI ownership handoff writes only the OS semaphore and waits for firmware release" {
    var reader = MockOwnershipReader{
        .header = USB_LEGACY_SUPPORT_CAPABILITY_ID | USB_LEGACY_BIOS_OWNED_SEMAPHORE,
        .release_after_reads = 3,
    };
    const legacy = (try findLegacySupport(0x40, &reader)).?;
    var deadline = MockOwnershipDeadline{ .remaining_checks = 4 };
    try std.testing.expectEqual(LegacyOwnership.os_owned, try claimLegacyOwnership(legacy, &reader, &deadline));
    try std.testing.expectEqual(@as(usize, 1), reader.os_write_count);
    try std.testing.expectEqual(@as(u32, 0x40), reader.last_write_offset);
    try std.testing.expectEqual(@as(u8, 1), reader.last_write_value);
    try std.testing.expect((reader.header & USB_LEGACY_OS_OWNED_SEMAPHORE) != 0);
    try std.testing.expect((reader.header & USB_LEGACY_BIOS_OWNED_SEMAPHORE) == 0);
}

test "xHCI ownership handoff accepts an already OS-owned controller" {
    var reader = MockOwnershipReader{
        .header = USB_LEGACY_SUPPORT_CAPABILITY_ID | USB_LEGACY_OS_OWNED_SEMAPHORE,
    };
    const legacy = (try findLegacySupport(0x40, &reader)).?;
    var deadline = MockOwnershipDeadline{ .remaining_checks = 0 };
    try std.testing.expectEqual(LegacyOwnership.os_owned, try claimLegacyOwnership(legacy, &reader, &deadline));
    try std.testing.expectEqual(@as(usize, 0), reader.os_write_count);
}

test "xHCI ownership handoff rejects failed requests, changed capabilities, and timeouts" {
    var rejected_reader = MockOwnershipReader{
        .header = USB_LEGACY_SUPPORT_CAPABILITY_ID | USB_LEGACY_BIOS_OWNED_SEMAPHORE,
        .accept_os_write = false,
    };
    const rejected_legacy = (try findLegacySupport(0x40, &rejected_reader)).?;
    var deadline = MockOwnershipDeadline{ .remaining_checks = 0 };
    try std.testing.expectError(
        error.OwnershipRequestRejected,
        claimLegacyOwnership(rejected_legacy, &rejected_reader, &deadline),
    );

    var changed_reader = MockOwnershipReader{
        .header = USB_LEGACY_SUPPORT_CAPABILITY_ID | USB_LEGACY_OS_OWNED_SEMAPHORE,
    };
    const changed_legacy = (try findLegacySupport(0x40, &changed_reader)).?;
    changed_reader.header = @as(u32, 2) | USB_LEGACY_OS_OWNED_SEMAPHORE;
    try std.testing.expectError(
        error.LegacyCapabilityChanged,
        claimLegacyOwnership(changed_legacy, &changed_reader, &deadline),
    );

    var timeout_reader = MockOwnershipReader{
        .header = USB_LEGACY_SUPPORT_CAPABILITY_ID | USB_LEGACY_BIOS_OWNED_SEMAPHORE,
    };
    const timeout_legacy = (try findLegacySupport(0x40, &timeout_reader)).?;
    deadline = .{ .remaining_checks = 2 };
    try std.testing.expectError(
        error.FirmwareOwnershipTimeout,
        claimLegacyOwnership(timeout_legacy, &timeout_reader, &deadline),
    );
}

test "xHCI capability parser rejects unsupported controllers" {
    var mmio = validCapabilityRegisters();
    mmio[CAPABILITY_LENGTH_OFFSET] = TEST_CAPABILITY_LENGTH + 1;
    try std.testing.expectError(error.InvalidCapabilityLength, testing.parseCapabilityRegisters(mmio[0..]));

    mmio = validCapabilityRegisters();
    writeU16Le(mmio[INTERFACE_VERSION_OFFSET .. INTERFACE_VERSION_OFFSET + U16_REGISTER_BYTES], TEST_UNSUPPORTED_INTERFACE_VERSION);
    try std.testing.expectError(error.UnsupportedVersion, testing.parseCapabilityRegisters(mmio[0..]));

    mmio = validCapabilityRegisters();
    writeU16Le(mmio[INTERFACE_VERSION_OFFSET .. INTERFACE_VERSION_OFFSET + U16_REGISTER_BYTES], 0x0100);
    try std.testing.expectError(error.UnsupportedVersion, testing.parseCapabilityRegisters(mmio[0..]));

    mmio = validCapabilityRegisters();
    writeU32Le(
        mmio[HCCPARAMS1_OFFSET .. HCCPARAMS1_OFFSET + U32_REGISTER_BYTES],
        HCCPARAMS1_CONTEXT_SIZE,
    );
    try std.testing.expectError(error.Unsupported32BitAddressing, testing.parseCapabilityRegisters(mmio[0..]));

    mmio = validCapabilityRegisters();
    writeU32Le(
        mmio[HCSPARAMS2_OFFSET .. HCSPARAMS2_OFFSET + U32_REGISTER_BYTES],
        HCSPARAMS2_SCRATCHPAD_RESTORE,
    );
    try std.testing.expectError(error.InvalidScratchpadRestore, testing.parseCapabilityRegisters(mmio[0..]));

    mmio = validCapabilityRegisters();
    writeU32Le(
        mmio[HCSPARAMS1_OFFSET .. HCSPARAMS1_OFFSET + U32_REGISTER_BYTES],
        (@as(u32, TEST_MAX_INTERRUPTERS) << HCSPARAMS1_MAX_INTERRUPTERS_SHIFT) |
            (@as(u32, TEST_MAX_PORTS) << HCSPARAMS1_MAX_PORTS_SHIFT),
    );
    try std.testing.expectError(error.MissingDeviceSlots, testing.parseCapabilityRegisters(mmio[0..]));

    mmio = validCapabilityRegisters();
    writeU32Le(
        mmio[HCSPARAMS1_OFFSET .. HCSPARAMS1_OFFSET + U32_REGISTER_BYTES],
        @as(u32, 32) | (@as(u32, 8) << HCSPARAMS1_MAX_INTERRUPTERS_SHIFT),
    );
    try std.testing.expectError(error.MissingPorts, testing.parseCapabilityRegisters(mmio[0..]));

    mmio = validCapabilityRegisters();
    writeU32Le(mmio[DOORBELL_OFFSET_OFFSET .. DOORBELL_OFFSET_OFFSET + U32_REGISTER_BYTES], TEST_DOORBELL_OFFSET + 1);
    try std.testing.expectError(error.InvalidDoorbellOffset, testing.parseCapabilityRegisters(mmio[0..]));

    mmio = validCapabilityRegisters();
    writeU32Le(mmio[RUNTIME_REGISTER_OFFSET_OFFSET .. RUNTIME_REGISTER_OFFSET_OFFSET + U32_REGISTER_BYTES], TEST_RUNTIME_REGISTER_OFFSET + 4);
    try std.testing.expectError(error.InvalidRuntimeRegisterOffset, testing.parseCapabilityRegisters(mmio[0..]));
}

pub const testing = struct {
    pub fn parseCapabilityRegisters(mmio: []const u8) Error!CapabilityRegisters {
        var out: CapabilityRegisters = undefined;
        try parseCapabilityRegistersInto(&out, mmio);
        return out;
    }

    pub fn parseSupportedProtocols(
        capabilities: CapabilityRegisters,
        first_offset: u32,
        reader: anytype,
    ) Error!SupportedProtocols {
        var out: SupportedProtocols = undefined;
        try parseSupportedProtocolsInto(&out, capabilities, first_offset, reader);
        return out;
    }

    pub fn inspectLegacyOwnership(first_offset: u32, reader: anytype) Error!LegacyOwnership {
        const legacy = try findLegacySupport(first_offset, reader) orelse return .not_present;
        if (legacy.firmware_owned) return error.FirmwareOwnsController;
        return if (legacy.os_owned) .os_owned else .firmware_released;
    }
};
