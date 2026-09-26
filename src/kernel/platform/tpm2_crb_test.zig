const std = @import("std");
const crb = @import("tpm2_crb.zig");
const endian = @import("../utils/endian.zig");
const checksum = @import("../utils/checksum.zig");

const physical_base = 0xfed4_0000;
const Fault = enum { none, locality, ready, command, cancel, oversized, header_changed, seized, device, idle, release };
const FakeIo = struct {
    regs: [0x70 / 4]u32 = @splat(0),
    memory: [crb.PAGE_BYTES]u8 = @splat(0),
    now: u32 = 0,
    fault: Fault = .none,
    submitted: bool = false,
    cancel_count: usize = 0,
    buffer_writes: usize = 0,
    buffer_reads: usize = 0,
    writes: usize = 0,
    command: [22]u8 = undefined,

    fn init(fault: Fault) FakeIo {
        var io = FakeIo{ .fault = fault };
        io.set(.locality_state, 0x80);
        io.set(.interface_id, (1 << 14) | 0x11);
        io.set(.status, 2);
        io.set(.command_address_low, physical_base + 0x80);
        io.set(.response_address_low, physical_base + 0x80);
        io.set(.command_size, crb.MAX_MESSAGE_BYTES);
        io.set(.response_size, crb.MAX_MESSAGE_BYTES);
        return io;
    }
    fn set(self: *FakeIo, reg: crb.Reg, value: u32) void {
        self.regs[@intFromEnum(reg) / 4] = value;
    }
    pub fn read(self: *FakeIo, reg: crb.Reg) u32 {
        return self.regs[@intFromEnum(reg) / 4];
    }
    pub fn write(self: *FakeIo, reg: crb.Reg, value: u32) void {
        self.writes += 1;
        self.set(reg, value);
        switch (reg) {
            .locality_control => {
                if (value == 1 and self.fault != .locality) {
                    self.set(.locality_state, 0x82);
                    self.set(.locality_status, 1);
                } else if (value == 2 and self.fault != .release) {
                    self.set(.locality_state, 0x80);
                    self.set(.locality_status, 0);
                }
            },
            .request => {
                if (value == 1 and self.fault == .ready) return;
                if (value == 2 and self.submitted and self.fault == .idle) return;
                self.set(.request, 0);
                self.set(.status, if (value == 2) 2 else 0);
            },
            .start => {
                self.submitted = true;
                @memcpy(&self.command, self.memory[0x80..][0..22]);
                if (self.fault == .command or self.fault == .cancel) return;
                self.set(.start, 0);
                if (self.fault == .seized) self.set(.locality_status, 2);
                if (self.fault == .device) self.set(.status, 1);
                const response = propertyReply(crb.FAMILY_INDICATOR, 0x322e_3000);
                @memcpy(self.memory[0x80..][0..27], &response);
                if (self.fault == .oversized) std.mem.writeInt(u32, self.memory[0x82..][0..4], 4097, .big);
            },
            .cancel => if (value == 1) {
                self.cancel_count += 1;
                if (self.fault != .cancel) self.set(.start, 0);
            },
            else => {},
        }
    }
    pub fn readBytes(self: *FakeIo, offset: usize, out: []u8) void {
        self.buffer_reads += 1;
        @memcpy(out, self.memory[offset..][0..out.len]);
        if (self.fault == .header_changed and self.buffer_reads == 2) out[9] ^= 1;
    }
    pub fn writeBytes(self: *FakeIo, offset: usize, bytes: []const u8) void {
        self.buffer_writes += 1;
        @memcpy(self.memory[offset..][0..bytes.len], bytes);
    }
    pub fn deadline(self: *FakeIo, milliseconds: u32) u32 {
        return self.now + milliseconds;
    }
    pub fn expired(self: *FakeIo, time: u32) bool {
        return self.now >= time;
    }
    pub fn pause(self: *FakeIo) void {
        self.now += 1;
    }
};

fn propertyReply(property: u32, value: u32) [27]u8 {
    var bytes: [27]u8 = @splat(0);
    std.mem.writeInt(u16, bytes[0..2], 0x8001, .big);
    std.mem.writeInt(u32, bytes[2..6], 27, .big);
    bytes[10] = 1;
    std.mem.writeInt(u32, bytes[11..15], 6, .big);
    std.mem.writeInt(u32, bytes[15..19], 1, .big);
    std.mem.writeInt(u32, bytes[19..23], property, .big);
    std.mem.writeInt(u32, bytes[23..27], value, .big);
    return bytes;
}

fn table() [52]u8 {
    var bytes: [52]u8 = @splat(0);
    @memcpy(bytes[0..4], "TPM2");
    endian.writeU32Le(bytes[4..8], bytes.len);
    bytes[8] = 4;
    endian.writeU64Le(bytes[40..48], physical_base + 0x40);
    endian.writeU32Le(bytes[48..52], 7);
    checksum.finishSum8Prefix(&bytes, 9, bytes.len);
    return bytes;
}

test "TPM2 ACPI discovery requires a validated direct CRB control page" {
    var bytes = table();
    try std.testing.expectEqual(physical_base, (try crb.parseAcpi(&bytes)).physical_base);
    bytes[8] = 5;
    checksum.finishSum8Prefix(&bytes, 9, bytes.len);
    _ = try crb.parseAcpi(&bytes);
    bytes[12] ^= 1;
    try std.testing.expectError(error.BadChecksum, crb.parseAcpi(&bytes));
    bytes = table();
    endian.writeU32Le(bytes[4..8], 48);
    checksum.finishSum8Prefix(&bytes, 9, 48);
    try std.testing.expectError(error.InvalidLength, crb.parseAcpi(&bytes));
    for ([_]u32{ 0, 2, 6, 8, 11, 13, 15 }) |method| {
        bytes = table();
        endian.writeU32Le(bytes[48..52], method);
        checksum.finishSum8Prefix(&bytes, 9, bytes.len);
        try std.testing.expectError(error.UnsupportedStartMethod, crb.parseAcpi(&bytes));
    }
    for ([_]u64{ 0, 0x40, physical_base, physical_base + 0x41, 0xffff_ffff_ffff_f040 }) |address| {
        bytes = table();
        endian.writeU64Le(bytes[40..48], address);
        checksum.finishSum8Prefix(&bytes, 9, bytes.len);
        try std.testing.expectError(error.InvalidAddress, crb.parseAcpi(&bytes));
    }
}

test "CRB buffers must fit entirely in the device page without covering registers" {
    const maximum = try crb.bufferWithinPage(physical_base, physical_base + 0x80, crb.MAX_MESSAGE_BYTES);
    try std.testing.expectEqual(@as(usize, 0x80), maximum.offset);
    _ = try crb.bufferWithinPage(physical_base, physical_base + 4096 - 10, 10);
    const bad = [_]struct { address: u64, bytes: u32 }{
        .{ .address = physical_base - 1, .bytes = 10 },
        .{ .address = physical_base + 0x7f, .bytes = 10 },
        .{ .address = physical_base + 4096, .bytes = 10 },
        .{ .address = physical_base + 4090, .bytes = 10 },
        .{ .address = physical_base + 128, .bytes = 9 },
        .{ .address = physical_base + 128, .bytes = 0xffff_ffff },
        .{ .address = 0xffff_ffff_ffff_ffff, .bytes = 10 },
    };
    for (bad) |item| try std.testing.expectError(error.UnsupportedBuffers, crb.bufferWithinPage(physical_base, item.address, item.bytes));
}

test "CRB executes repeated commands with locality ownership and idle handoff" {
    var io = FakeIo.init(.none);
    var transport = crb.Transport{ .discovery = .{ .physical_base = physical_base } };
    const command = crb.propertyCommand(crb.FAMILY_INDICATOR);
    var response: [27]u8 = undefined;
    for (0..3) |_| {
        const reply = try transport.execute(&io, &command, &response, 2000);
        try std.testing.expectEqual(@as(u32, 0x322e_3000), try crb.parseProperty(reply, crb.FAMILY_INDICATOR));
        try std.testing.expectEqualSlices(u8, &command, &io.command);
        try std.testing.expectEqual(@as(u32, 0), io.read(.locality_status));
        try std.testing.expectEqual(@as(u32, 2), io.read(.status));
    }
    try std.testing.expectEqual(@as(usize, 3), io.buffer_writes);
    try std.testing.expectEqual(@as(u32, 0), io.now);
}

test "CRB invalid callers do not access hardware or disable the transport" {
    var io = FakeIo.init(.none);
    var transport = crb.Transport{ .discovery = .{ .physical_base = physical_base } };
    var command = crb.propertyCommand(crb.FAMILY_INDICATOR);
    var response: [27]u8 = @splat(0xaa);
    try std.testing.expectError(error.InvalidCommand, transport.execute(&io, command[0..9], &response, 2000));
    try std.testing.expectError(error.InvalidCommand, transport.execute(&io, &command, &response, 0));
    try std.testing.expectError(error.InvalidCommand, transport.execute(&io, &command, response[0..9], 2000));
    command[5] += 1;
    try std.testing.expectError(error.InvalidCommand, transport.execute(&io, &command, &response, 2000));
    try std.testing.expect(!transport.failed);
    try std.testing.expectEqual(@as(usize, 0), io.writes);
    try std.testing.expectEqualSlices(u8, &(@as([27]u8, @splat(0xaa))), &response);
}

test "CRB rejects device faults with bounded cleanup and a permanent failure latch" {
    const cases = [_]struct { fault: Fault, err: crb.Error }{
        .{ .fault = .locality, .err = error.LocalityTimeout },
        .{ .fault = .ready, .err = error.InterfaceTimeout },
        .{ .fault = .command, .err = error.CommandTimeout },
        .{ .fault = .cancel, .err = error.CommandTimeout },
        .{ .fault = .oversized, .err = error.ResponseTooLarge },
        .{ .fault = .header_changed, .err = error.InvalidResponse },
        .{ .fault = .seized, .err = error.LocalityLost },
        .{ .fault = .device, .err = error.DeviceError },
        .{ .fault = .idle, .err = error.InterfaceTimeout },
        .{ .fault = .release, .err = error.LocalityTimeout },
    };
    for (cases) |case| {
        var io = FakeIo.init(case.fault);
        var transport = crb.Transport{ .discovery = .{ .physical_base = physical_base } };
        const command = crb.propertyCommand(crb.FAMILY_INDICATOR);
        var response: [27]u8 = @splat(0xaa);
        try std.testing.expectError(case.err, transport.execute(&io, &command, &response, 2000));
        try std.testing.expect(transport.failed);
        try std.testing.expect(io.now <= 4000);
        try std.testing.expectEqualSlices(u8, &(@as([27]u8, @splat(0))), &response);
        const writes = io.writes;
        try std.testing.expectError(error.DeviceFailed, transport.execute(&io, &command, &response, 2000));
        try std.testing.expectEqual(writes, io.writes);
        if (case.fault == .command or case.fault == .cancel) try std.testing.expectEqual(@as(usize, 1), io.cancel_count);
        if (case.fault == .cancel) try std.testing.expectEqual(@as(u32, 1), io.read(.start));
        if (case.fault == .oversized) try std.testing.expectEqual(@as(usize, 1), io.buffer_reads);
        if (case.fault == .locality or case.fault == .ready) try std.testing.expectEqual(@as(usize, 0), io.buffer_writes);
    }
}

test "TPM property replies reject malformed framing and wrong property selectors" {
    const good = propertyReply(crb.FAMILY_INDICATOR, 0x322e_3000);
    try std.testing.expectEqual(@as(u32, 0x322e_3000), try crb.parseProperty(&good, crb.FAMILY_INDICATOR));
    try std.testing.expectError(error.InvalidResponse, crb.parseProperty(&good, crb.MANUFACTURER));
    for (0..good.len) |length| try std.testing.expectError(error.InvalidResponse, crb.parseProperty(good[0..length], crb.FAMILY_INDICATOR));
    for ([_]usize{ 0, 1, 2, 5, 10, 11, 14, 15, 18, 19, 22 }) |offset| {
        var bytes = good;
        bytes[offset] ^= 0x40;
        try std.testing.expectError(error.InvalidResponse, crb.parseProperty(&bytes, crb.FAMILY_INDICATOR));
    }
}
