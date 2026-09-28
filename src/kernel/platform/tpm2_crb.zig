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
    Busy,
    Cancelled,
    NoCommand,
    TicketExhausted,
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

fn ownsLocality(io: anytype) bool {
    return io.read(.locality_state) & 0x9e == 0x82 and io.read(.locality_status) & 3 == 1;
}

fn healthy(io: anytype) Error!void {
    if (!ownsLocality(io)) return error.LocalityLost;
    if (io.read(.status) & 1 != 0) return error.DeviceError;
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

// The caller serializes access to the transport and retains each operation at
// one exclusive owner. Interface faults latch failure until reboot: a lost
// response must never cause an implicit retry of a possibly completed command.
pub const Transport = struct {
    discovery: Discovery,
    failed: bool = false,
    busy: bool = false,

    // Borrows both buffers until poll returns a response or an error. begin does
    // no MMIO. Neither the operation nor the transport may be copied while live.
    pub fn begin(self: *Transport, io: anytype, command: []const u8, response: []u8, timeout_ms: u32) Error!Operation(@TypeOf(io.deadline(LOCALITY_TIMEOUT_MS))) {
        if (self.busy) return error.Busy;
        if (self.failed) return error.DeviceFailed;
        const request = parseHeader(command) catch return error.InvalidCommand;
        if (request.bytes != command.len or command.len > MAX_MESSAGE_BYTES or
            response.len < HEADER_BYTES or response.len > MAX_MESSAGE_BYTES or
            timeout_ms == 0 or timeout_ms > MAX_COMMAND_TIMEOUT_MS) return error.InvalidCommand;
        self.busy = true;
        return .{
            .transport = self,
            .command = command,
            .response = response,
            .request_tag = request.tag,
            .timeout_ms = timeout_ms,
            .deadline = io.deadline(LOCALITY_TIMEOUT_MS),
        };
    }

    // Boot/proof adapter. All protocol transitions and cleanup use the same
    // pollable engine; only this explicitly synchronous adapter spins.
    pub fn execute(self: *Transport, io: anytype, command: []const u8, response: []u8, timeout_ms: u32) Error![]u8 {
        var operation = try self.begin(io, command, response, timeout_ms);
        while (true) {
            if (try operation.poll(io)) |reply| return reply;
            // A phase transition can be driven immediately; pause only when a
            // hardware condition remains pending, preserving the boot fast path.
            if (operation.waiting) io.pause();
        }
    }
};

pub fn Operation(comptime Deadline: type) type {
    return struct {
        const Self = @This();
        const Phase = enum {
            initial,
            locality,
            idle_ack,
            idle_status,
            ready_ack,
            ready_status,
            running,
            release,
            cleanup,
            cancel_wait,
            cleanup_release,
            done,
        };
        const AfterIdle = enum { submit, release, cleanup };

        transport: *Transport,
        command: []const u8,
        response: []u8,
        request_tag: u16,
        timeout_ms: u32,
        deadline: Deadline,
        phase: Phase = .initial,
        after_idle: AfterIdle = .submit,
        command_buffer: Buffer = .{ .offset = 0, .bytes = 0 },
        response_buffer: Buffer = .{ .offset = 0, .bytes = 0 },
        response_bytes: usize = 0,
        failure: ?Error = null,
        requested: bool = false,
        acquired: bool = false,
        release_issued: bool = false,
        cancelled: bool = false,
        waiting: bool = false,

        // Cancellation suppresses the result, not the command's possible side
        // effects. Keep polling and retain both buffers until cleanup terminates.
        pub fn cancel(self: *Self) void {
            if (self.phase != .done) self.cancelled = true;
        }

        // One bounded phase per call; no spin, sleep, allocation, or callback.
        // null means pending (including cleanup). An error is terminal, so the
        // caller can safely release its buffers even after cancellation.
        pub fn poll(self: *Self, io: anytype) Error!?[]u8 {
            if (self.phase == .done) return error.NoCommand;
            self.waiting = false;
            if (self.cancelled and self.failure == null) self.fail(error.Cancelled);
            return self.step(io) catch |err| {
                if (self.phase == .done) return err;
                self.fail(err);
                return null;
            };
        }

        fn fail(self: *Self, err: Error) void {
            if (err != error.Cancelled) self.transport.failed = true;
            if (self.failure == null) self.failure = err;
            std.crypto.secureZero(u8, self.response);
            self.command = &.{};
            self.phase = .cleanup;
        }

        fn wait(self: *Self, io: anytype, reg: Reg, mask: u32, value: u32, err: Error) Error!bool {
            if (io.read(reg) & mask == value) return true;
            if (io.expired(self.deadline)) return err;
            self.waiting = true;
            return false;
        }

        fn enter(self: *Self, io: anytype, phase: Phase, timeout: u32) void {
            self.phase = phase;
            self.deadline = io.deadline(timeout);
        }

        fn idle(self: *Self, io: anytype, after: AfterIdle) void {
            self.after_idle = after;
            io.write(.request, 2);
            self.enter(io, .idle_ack, INTERFACE_TIMEOUT_MS);
        }

        fn release(self: *Self, io: anytype, cleanup: bool) void {
            self.release_issued = true;
            io.write(.locality_control, 2);
            self.enter(io, if (cleanup) .cleanup_release else .release, LOCALITY_TIMEOUT_MS);
        }

        fn finish(self: *Self) Error!?[]u8 {
            const reply = self.response[0..self.response_bytes];
            const failure = self.failure;
            self.command = &.{};
            self.response = &.{};
            self.command_buffer = .{ .offset = 0, .bytes = 0 };
            self.response_buffer = .{ .offset = 0, .bytes = 0 };
            self.response_bytes = 0;
            self.transport.busy = false;
            self.phase = .done;
            if (failure) |err| return err;
            return reply;
        }

        fn step(self: *Self, io: anytype) Error!?[]u8 {
            switch (self.phase) {
                .initial => {
                    if (!try self.wait(io, .locality_state, 0x80, 0x80, error.LocalityTimeout)) return null;
                    const interface = io.read(.interface_id);
                    const version = (interface >> 4) & 0xf;
                    if (interface & 0xf != 1 or version < 1 or version > 3 or interface & (1 << 14) == 0)
                        return error.UnsupportedInterface;
                    self.requested = true;
                    io.write(.locality_control, 1);
                    self.enter(io, .locality, LOCALITY_TIMEOUT_MS);
                },
                .locality => {
                    if (!try self.wait(io, .locality_state, 0x9e, 0x82, error.LocalityTimeout)) return null;
                    try healthy(io);
                    self.acquired = true;
                    if (io.read(.start) & 1 != 0) return error.DeviceError;
                    const base = self.transport.discovery.physical_base;
                    self.command_buffer = try bufferWithinPage(base, readAddress(io, .command_address_low, .command_address_high), io.read(.command_size));
                    self.response_buffer = try bufferWithinPage(base, readAddress(io, .response_address_low, .response_address_high), io.read(.response_size));
                    if (self.command.len > self.command_buffer.bytes) return error.InvalidCommand;
                    self.idle(io, .submit);
                },
                .idle_ack, .idle_status => {
                    // Cleanup errors proceed straight to release; restarting the
                    // same idle wait would turn a deadline into an infinite loop.
                    self.pollIdle(io) catch |err| {
                        if (self.failure == null) return err;
                        self.transport.failed = true;
                        self.release(io, true);
                    };
                },
                .ready_ack => {
                    try healthy(io);
                    if (!try self.wait(io, .request, 1, 0, error.InterfaceTimeout)) return null;
                    self.enter(io, .ready_status, INTERFACE_TIMEOUT_MS);
                },
                .ready_status => {
                    try healthy(io);
                    if (!try self.wait(io, .status, 2, 0, error.InterfaceTimeout)) return null;
                    io.write(.cancel, 0);
                    io.writeBytes(self.command_buffer.offset, self.command);
                    self.command = &.{};
                    io.write(.start, 1);
                    self.enter(io, .running, self.timeout_ms);
                },
                .running => {
                    try healthy(io);
                    if (!try self.wait(io, .start, 1, 0, error.CommandTimeout)) return null;
                    var header_bytes: [HEADER_BYTES]u8 = undefined;
                    io.readBytes(self.response_buffer.offset, &header_bytes);
                    const reply = try parseHeader(&header_bytes);
                    if (reply.bytes > self.response_buffer.bytes or reply.bytes > self.response.len) return error.ResponseTooLarge;
                    if (reply.code != 0) {
                        if (reply.tag != 0x8001 or reply.bytes != HEADER_BYTES) return error.InvalidResponse;
                    } else if (reply.tag != self.request_tag) return error.InvalidResponse;
                    io.readBytes(self.response_buffer.offset, self.response[0..reply.bytes]);
                    if (!std.mem.eql(u8, &header_bytes, self.response[0..HEADER_BYTES])) return error.InvalidResponse;
                    try healthy(io);
                    self.response_bytes = reply.bytes;
                    self.idle(io, .release);
                },
                .release => {
                    if (!try self.wait(io, .locality_status, 1, 0, error.LocalityTimeout)) return null;
                    return self.finish();
                },
                .cleanup => {
                    if (!self.requested) return self.finish();
                    if (ownsLocality(io)) {
                        if (io.read(.status) & 1 != 0) self.transport.failed = true;
                        if (io.read(.start) & 1 != 0) {
                            io.write(.cancel, 1);
                            self.enter(io, .cancel_wait, CANCEL_TIMEOUT_MS);
                        } else {
                            io.write(.cancel, 0);
                            self.idle(io, .cleanup);
                        }
                    } else {
                        if (self.acquired and !self.release_issued) self.transport.failed = true;
                        self.release(io, true);
                    }
                },
                .cancel_wait => {
                    if (!ownsLocality(io)) {
                        self.transport.failed = true;
                        self.release(io, true);
                        return null;
                    }
                    const stopped = self.wait(io, .start, 1, 0, error.CommandTimeout) catch {
                        self.transport.failed = true;
                        // Still running: do not access buffers or idle/release.
                        return self.finish();
                    };
                    if (!stopped) return null;
                    if (io.read(.status) & 1 != 0) self.transport.failed = true;
                    io.write(.cancel, 0);
                    self.idle(io, .cleanup);
                },
                .cleanup_release => {
                    const released = self.wait(io, .locality_status, 1, 0, error.LocalityTimeout) catch {
                        self.transport.failed = true;
                        return self.finish();
                    };
                    if (released) return self.finish();
                },
                .done => unreachable,
            }
            return null;
        }

        fn pollIdle(self: *Self, io: anytype) Error!void {
            try healthy(io);
            if (self.phase == .idle_ack) {
                if (!try self.wait(io, .request, 2, 0, error.InterfaceTimeout)) return;
                self.enter(io, .idle_status, INTERFACE_TIMEOUT_MS);
                return;
            }
            if (!try self.wait(io, .status, 2, 2, error.InterfaceTimeout)) return;
            switch (self.after_idle) {
                .submit => {
                    io.write(.request, 1);
                    self.enter(io, .ready_ack, INTERFACE_TIMEOUT_MS);
                },
                .release => self.release(io, false),
                .cleanup => self.release(io, true),
            }
        }
    };
}

// A kernel-private token fences stale poll/cancel calls from the next command.
// The slot, transport and borrowed buffers must remain at stable addresses;
// callers serialize every slot access, but need not hold a lock between polls.
pub const Ticket = enum(u64) { _ };

pub fn CommandSlot(comptime Deadline: type) type {
    return struct {
        operation: ?Operation(Deadline) = null,
        current: Ticket = @enumFromInt(0),
        next_ticket: u64 = 1,

        pub fn begin(self: *@This(), transport: *Transport, io: anytype, command: []const u8, response: []u8, timeout_ms: u32) Error!Ticket {
            if (self.operation != null) return error.Busy;
            if (self.next_ticket == 0) return error.TicketExhausted;
            self.operation = try transport.begin(io, command, response, timeout_ms);
            self.current = @enumFromInt(self.next_ticket);
            self.next_ticket +%= 1;
            return self.current;
        }

        pub fn poll(self: *@This(), io: anytype, ticket: Ticket) Error!?[]u8 {
            if (ticket != self.current) return error.NoCommand;
            const operation = if (self.operation) |*value| value else return error.NoCommand;
            const reply = operation.poll(io) catch |err| {
                self.operation = null;
                return err;
            };
            if (reply != null) self.operation = null;
            return reply;
        }

        pub fn cancel(self: *@This(), ticket: Ticket) Error!void {
            if (ticket != self.current) return error.NoCommand;
            const operation = if (self.operation) |*value| value else return error.NoCommand;
            operation.cancel();
        }
    };
}

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
