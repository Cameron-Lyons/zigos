const std = @import("std");
const acpi = @import("acpi.zig");
const endian = @import("../utils/endian.zig");

// TCG ACPI 1.4, table 7; PC Client PTP 1.07, sections 6.4.2 and 6.5.3.
// Only the direct CRB start method and one device-backed locality page are
// supported. Firmware-mediated starts, FIFO, RAM CRB, and chunking are not used.
pub const SIGNATURE = "TPM2";
pub const PAGE_BYTES: usize = 4096;
pub const HEADER_BYTES: usize = 10;
pub const MAX_MESSAGE_BYTES: usize = PAGE_BYTES - 0x80;
const MAX_PHYSICAL_ADDRESS: u64 = 0x000f_ffff_ffff_ffff;
pub const INTERFACE_TIMEOUT_MS = 200;
pub const LOCALITY_TIMEOUT_MS = 750;
pub const CANCEL_TIMEOUT_MS = 2000;
pub const MAX_COMMAND_TIMEOUT_MS = 120_000;

pub const Reg = enum(usize) {
    locality_state = 0,
    locality_control = 8,
    locality_status = 12,
    interface_id = 0x30,
    request = 0x40,
    status = 0x44,
    cancel = 0x48,
    start = 0x4c,
    command_size = 0x58,
    command_address_low = 0x5c,
    command_address_high = 0x60,
    response_size = 0x64,
    response_address_low = 0x68,
    response_address_high = 0x6c,
};

pub const Error = error{
    UnsupportedRevision,
    UnsupportedStartMethod,
    InvalidAddress,
    UnsupportedInterface,
    UnsupportedBuffers,
    InvalidCommand,
    InvalidResponse,
    ResponseTooLarge,
    LocalityTimeout,
    InterfaceTimeout,
    CommandTimeout,
    LocalityLost,
    DeviceError,
    DeviceFailed,
};

pub const Discovery = struct {
    physical_base: u64,
};

pub fn parseAcpi(table: []const u8) (acpi.SdtError || Error)!Discovery {
    const header = try acpi.parseSdtHeader(table);
    if (!std.mem.eql(u8, &header.signature, SIGNATURE)) return error.BadSignature;
    if (header.revision != 4 and header.revision != 5) return error.UnsupportedRevision;
    if (header.length < 52) return error.InvalidLength;
    if (endian.readU32Le(table[48..52]) != 7) return error.UnsupportedStartMethod;
    const control_address = endian.readU64Le(table[40..48]);
    if (control_address < PAGE_BYTES or control_address & (PAGE_BYTES - 1) != 0x40 or
        control_address > MAX_PHYSICAL_ADDRESS - PAGE_BYTES)
        return error.InvalidAddress;
    return .{ .physical_base = control_address - 0x40 };
}

pub const Buffer = struct { offset: usize, bytes: usize };

pub fn bufferWithinPage(base: u64, address: u64, bytes: u32) Error!Buffer {
    if (address < base or address - base < 0x80 or address - base >= PAGE_BYTES or
        bytes < HEADER_BYTES or bytes > PAGE_BYTES - (address - base))
        return error.UnsupportedBuffers;
    return .{ .offset = @intCast(address - base), .bytes = bytes };
}

fn readAddress(io: anytype, low: Reg, high: Reg) u64 {
    return @as(u64, io.read(low)) | (@as(u64, io.read(high)) << 32);
}

fn wait(io: anytype, reg: Reg, mask: u32, value: u32, milliseconds: u32) bool {
    const deadline = io.deadline(milliseconds);
    while (true) {
        if (io.read(reg) & mask == value) return true;
        if (io.expired(deadline)) return false;
        io.pause();
    }
}

fn ownsLocality(io: anytype) bool {
    return io.read(.locality_state) & 0x9e == 0x82 and io.read(.locality_status) & 3 == 1;
}

fn healthy(io: anytype) Error!void {
    if (!ownsLocality(io)) return error.LocalityLost;
    if (io.read(.status) & 1 != 0) return error.DeviceError;
}

fn idle(io: anytype) Error!void {
    io.write(.request, 2);
    if (!wait(io, .request, 2, 0, INTERFACE_TIMEOUT_MS) or
        !wait(io, .status, 2, 2, INTERFACE_TIMEOUT_MS)) return error.InterfaceTimeout;
    try healthy(io);
}

fn release(io: anytype) Error!void {
    io.write(.locality_control, 2);
    if (!wait(io, .locality_status, 1, 0, LOCALITY_TIMEOUT_MS)) return error.LocalityTimeout;
}

pub const Header = struct {
    tag: u16,
    bytes: u32,
    code: u32,
};

pub fn parseHeader(bytes: []const u8) Error!Header {
    if (bytes.len < HEADER_BYTES) return error.InvalidResponse;
    const tag = std.mem.readInt(u16, bytes[0..2], .big);
    const length = std.mem.readInt(u32, bytes[2..6], .big);
    if ((tag != 0x8001 and tag != 0x8002) or length < HEADER_BYTES)
        return error.InvalidResponse;
    return .{ .tag = tag, .bytes = length, .code = std.mem.readInt(u32, bytes[6..10], .big) };
}

// The caller serializes access. An interface fault latches failure until reboot;
// retrying a timed-out command could repeat an operation whose result was lost.
// io supplies register/buffer access, a monotonic deadline, and a polling hint.
pub const Transport = struct {
    discovery: Discovery,
    failed: bool = false,

    pub fn execute(self: *Transport, io: anytype, command: []const u8, response: []u8, timeout_ms: u32) Error![]u8 {
        if (self.failed) return error.DeviceFailed;
        const request = parseHeader(command) catch return error.InvalidCommand;
        if (request.bytes != command.len or command.len > MAX_MESSAGE_BYTES or
            response.len < HEADER_BYTES or response.len > MAX_MESSAGE_BYTES or
            timeout_ms == 0 or timeout_ms > MAX_COMMAND_TIMEOUT_MS) return error.InvalidCommand;

        var requested = false;
        errdefer {
            self.failed = true;
            @memset(response, 0);
            // Never touch a buffer while a command might still be running or a
            // higher locality owns the device. Cancellation itself is bounded.
            if (requested and ownsLocality(io)) {
                if (io.read(.start) & 1 != 0) {
                    io.write(.cancel, 1);
                    _ = wait(io, .start, 1, 0, CANCEL_TIMEOUT_MS);
                }
                if (ownsLocality(io) and io.read(.start) & 1 == 0) {
                    io.write(.cancel, 0);
                    idle(io) catch {};
                    release(io) catch {};
                }
            } else if (requested) {
                // Relinquish also cancels a pending locality request.
                io.write(.locality_control, 2);
            }
        }

        if (!wait(io, .locality_state, 0x80, 0x80, LOCALITY_TIMEOUT_MS)) return error.LocalityTimeout;
        const interface = io.read(.interface_id);
        const version = (interface >> 4) & 0xf;
        if (interface & 0xf != 1 or version < 1 or version > 3 or interface & (1 << 14) == 0)
            return error.UnsupportedInterface;
        requested = true;
        io.write(.locality_control, 1);
        if (!wait(io, .locality_state, 0x9e, 0x82, LOCALITY_TIMEOUT_MS)) return error.LocalityTimeout;
        try healthy(io);
        if (io.read(.start) & 1 != 0) return error.DeviceError;

        const command_buffer = try bufferWithinPage(self.discovery.physical_base, readAddress(io, .command_address_low, .command_address_high), io.read(.command_size));
        const response_buffer = try bufferWithinPage(self.discovery.physical_base, readAddress(io, .response_address_low, .response_address_high), io.read(.response_size));
        if (command.len > command_buffer.bytes) return error.InvalidCommand;
        try idle(io);
        io.write(.request, 1);
        if (!wait(io, .request, 1, 0, INTERFACE_TIMEOUT_MS) or
            !wait(io, .status, 2, 0, INTERFACE_TIMEOUT_MS)) return error.InterfaceTimeout;
        try healthy(io);
        io.write(.cancel, 0);
        io.writeBytes(command_buffer.offset, command);
        io.write(.start, 1);
        if (!wait(io, .start, 1, 0, timeout_ms)) return error.CommandTimeout;
        try healthy(io);

        var header_bytes: [HEADER_BYTES]u8 = undefined;
        io.readBytes(response_buffer.offset, &header_bytes);
        const reply = try parseHeader(&header_bytes);
        if (reply.bytes > response_buffer.bytes or reply.bytes > response.len) return error.ResponseTooLarge;
        if (reply.code != 0) {
            if (reply.tag != 0x8001 or reply.bytes != HEADER_BYTES) return error.InvalidResponse;
        } else if (reply.tag != request.tag) return error.InvalidResponse;
        io.readBytes(response_buffer.offset, response[0..reply.bytes]);
        // A device must not change its header between the bounded header read
        // and payload read. Do not expose a mixed response to the caller.
        if (!std.mem.eql(u8, &header_bytes, response[0..HEADER_BYTES])) return error.InvalidResponse;
        try healthy(io);
        try idle(io);
        try release(io);
        return response[0..reply.bytes];
    }
};

pub const FAMILY_INDICATOR: u32 = 0x100;
pub const MANUFACTURER: u32 = 0x105;

pub fn propertyCommand(property: u32) [22]u8 {
    var command = [_]u8{ 0x80, 1, 0, 0, 0, 22, 0, 0, 1, 0x7a, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 1 };
    std.mem.writeInt(u32, command[14..18], property, .big);
    return command;
}

pub fn parseProperty(response: []const u8, property: u32) Error!u32 {
    const header = try parseHeader(response);
    if (header.code != 0) return error.DeviceError;
    if (header.tag != 0x8001 or header.bytes != 27 or response.len != 27 or response[10] > 1 or
        std.mem.readInt(u32, response[11..15], .big) != 6 or
        std.mem.readInt(u32, response[15..19], .big) != 1 or
        std.mem.readInt(u32, response[19..23], .big) != property) return error.InvalidResponse;
    return std.mem.readInt(u32, response[23..27], .big);
}
