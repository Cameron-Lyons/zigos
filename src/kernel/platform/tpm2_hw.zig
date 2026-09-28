const std = @import("std");
const crb = @import("tpm2_crb.zig");
const paging = @import("../memory/paging64.zig");
const windows = @import("../memory/mmio_windows.zig");
const clock = @import("../timer/tsc_clock.zig");
const spin = @import("../utils/spin.zig");
const interrupt_context = @import("../interrupts/context.zig");

pub const Error = crb.Error || error{ AlreadyInitialized, Unavailable, Busy, InterruptContext };
var attempted = false;
var online = false;
var transport: crb.Transport = undefined;
var lock = spin.Lock.init();
var commands = crb.CommandSlot(clock.Deadline){};
pub const Ticket = crb.Ticket;

// Boot CPU only, after paging and the invariant clock are initialized. No TPM
// ownership, PCR, hierarchy, persistent-object, or NV state is changed by probe.
pub fn initialize(discovery: crb.Discovery) Error!u32 {
    if (attempted) return error.AlreadyInitialized;
    attempted = true;
    const base = discovery.physical_base;
    if (base == 0 or base & (crb.PAGE_BYTES - 1) != 0 or base > 0x000f_ffff_ffff_f000)
        return error.InvalidAddress;
    paging.mapKernelBorrowedPage(windows.tpm_crb.base, @intCast(base), paging.PAGE_PRESENT | paging.PAGE_WRITABLE | paging.PAGE_CACHE_DISABLE | paging.PAGE_WRITE_THROUGH);
    transport = .{ .discovery = discovery };
    var io = HardwareIo{};
    var response: [27]u8 = undefined;
    defer std.crypto.secureZero(u8, &response);
    const family_command = crb.propertyCommand(crb.FAMILY_INDICATOR);
    const family_reply = try transport.execute(&io, &family_command, &response, 2000);
    if (try crb.parseProperty(family_reply, crb.FAMILY_INDICATOR) != 0x322e_3000)
        return error.UnsupportedInterface;
    const manufacturer_command = crb.propertyCommand(crb.MANUFACTURER);
    const manufacturer_reply = try transport.execute(&io, &manufacturer_command, &response, 2000);
    const manufacturer = try crb.parseProperty(manufacturer_reply, crb.MANUFACTURER);
    online = true;
    return manufacturer;
}

// Every entry holds the lock only for bounded work. A live command owns its
// borrowed buffers and transport slot across calls without retaining a spinlock.
fn acquire() Error!void {
    if (interrupt_context.active()) return error.InterruptContext;
    if (!lock.tryAcquire()) return error.Busy;
}

pub fn begin(command: []const u8, response: []u8, timeout_ms: u32) Error!Ticket {
    try acquire();
    defer lock.release();
    if (!online) return error.Unavailable;
    var io = HardwareIo{};
    return commands.begin(&transport, &io, command, response, timeout_ms);
}

// null is pending. Retain buffers and keep polling after cancel, through the
// terminal response/error. Busy and InterruptContext reject entry without
// retiring the command. A stale ticket never operates on a newer command.
pub fn poll(ticket: Ticket) Error!?[]u8 {
    try acquire();
    defer lock.release();
    var io = HardwareIo{};
    return commands.poll(&io, ticket);
}

pub fn cancel(ticket: Ticket) Error!void {
    try acquire();
    defer lock.release();
    return commands.cancel(ticket);
}

// Explicit synchronous adapter for existing boot and identity protocol callers.
// The authentication worker can drive begin/poll/cancel without blocking here.
pub fn execute(command: []const u8, response: []u8, timeout_ms: u32) Error![]u8 {
    const ticket = try begin(command, response, timeout_ms);
    while (true) {
        // Contention before poll acquires the lock does not retire the command.
        // Keep ownership until its terminal result rather than abandoning a
        // borrowed stack buffer while the TPM can still write its reply.
        const reply = poll(ticket) catch |err| switch (err) {
            error.Busy => {
                spin.hint();
                continue;
            },
            else => return err,
        };
        if (reply) |bytes| return bytes;
        spin.hint();
    }
}

pub fn available() bool {
    acquire() catch return false;
    defer lock.release();
    return online and !transport.failed;
}

const HardwareIo = struct {
    pub fn read(_: *HardwareIo, reg: crb.Reg) u32 {
        const ptr: *volatile u32 = @ptrFromInt(windows.tpm_crb.base + @intFromEnum(reg));
        return ptr.*;
    }
    pub fn write(_: *HardwareIo, reg: crb.Reg, value: u32) void {
        const ptr: *volatile u32 = @ptrFromInt(windows.tpm_crb.base + @intFromEnum(reg));
        asm volatile ("" ::: .{ .memory = true });
        ptr.* = value;
        asm volatile ("" ::: .{ .memory = true });
    }
    pub fn readBytes(_: *HardwareIo, offset: usize, out: []u8) void {
        std.debug.assert(offset >= 0x80 and offset + out.len <= crb.PAGE_BYTES);
        const ptr: [*]volatile u8 = @ptrFromInt(windows.tpm_crb.base + offset);
        for (out, 0..) |*byte, index| byte.* = ptr[index];
    }
    pub fn writeBytes(_: *HardwareIo, offset: usize, bytes: []const u8) void {
        std.debug.assert(offset >= 0x80 and offset + bytes.len <= crb.PAGE_BYTES);
        const ptr: [*]volatile u8 = @ptrFromInt(windows.tpm_crb.base + offset);
        for (bytes, 0..) |byte, index| ptr[index] = byte;
    }
    pub fn deadline(_: *HardwareIo, milliseconds: u32) clock.Deadline {
        return clock.afterMilliseconds(milliseconds);
    }
    pub fn expired(_: *HardwareIo, value: clock.Deadline) bool {
        return value.expired();
    }
    pub fn pause(_: *HardwareIo) void {
        spin.hint();
    }
};
