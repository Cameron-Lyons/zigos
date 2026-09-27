const builtin = @import("builtin");
const x86 = if (builtin.target.os.tag == .freestanding)
    @import("../../arch/x86.zig")
else
    struct {
        pub fn readMsr(_: u32) u64 {
            return 0;
        }
        pub fn writeMsr(_: u32, _: u64) void {}
    };

const X2APIC_ID_MSR: u32 = 0x802;
const X2APIC_EOI_MSR: u32 = 0x80B;
const X2APIC_ICR_MSR: u32 = 0x830;
const X2APIC_SPURIOUS_VECTOR_MSR: u32 = 0x80F;
const IA32_APIC_BASE_MSR: u32 = 0x1B;

const APIC_GLOBAL_ENABLE: u64 = 1 << 11;
const X2APIC_ENABLE: u64 = 1 << 10;
const X2APIC_SOFTWARE_ENABLE: u64 = 1 << 8;

pub const SPURIOUS_VECTOR: u8 = 0xFF;
pub const STARTS_APPLICATION_PROCESSORS = true;

pub const DeliveryMode = enum(u3) {
    fixed = 0,
    init = 5,
    startup = 6,
};

pub const Icr = struct {
    destination: u32,
    vector: u8 = 0,
    delivery: DeliveryMode = .fixed,
};

pub fn localId() u32 {
    return @truncate(x86.readMsr(X2APIC_ID_MSR));
}

pub fn acknowledge() void {
    x86.writeMsr(X2APIC_EOI_MSR, 0);
}

pub fn icrValue(command: Icr) u64 {
    return @as(u64, command.vector) |
        (@as(u64, @intFromEnum(command.delivery)) << 8) |
        (@as(u64, command.destination) << 32);
}

pub fn sendIpi(command: Icr) void {
    x86.writeMsr(X2APIC_ICR_MSR, icrValue(command));
}

pub fn sendInit(apic_id: u32) void {
    sendIpi(.{ .destination = apic_id, .delivery = .init });
}

pub fn sendStartup(apic_id: u32, vector: u8) void {
    sendIpi(.{ .destination = apic_id, .vector = vector, .delivery = .startup });
}

pub fn enable() void {
    x86.writeMsr(
        IA32_APIC_BASE_MSR,
        x86.readMsr(IA32_APIC_BASE_MSR) | APIC_GLOBAL_ENABLE | X2APIC_ENABLE,
    );
    const spurious = x86.readMsr(X2APIC_SPURIOUS_VECTOR_MSR);
    x86.writeMsr(
        X2APIC_SPURIOUS_VECTOR_MSR,
        (spurious & ~@as(u64, 0xFF)) | X2APIC_SOFTWARE_ENABLE | SPURIOUS_VECTOR,
    );
}

const std = @import("std");

test "x2APIC ICR encodes INIT, SIPI, and TLB vectors" {
    try std.testing.expectEqual(
        @as(u64, 0x0000_0002_0000_0500),
        icrValue(.{ .destination = 2, .delivery = .init }),
    );
    try std.testing.expectEqual(
        @as(u64, 0x0000_0003_0000_0608),
        icrValue(.{ .destination = 3, .vector = 8, .delivery = .startup }),
    );
    try std.testing.expectEqual(
        @as(u64, 0x0000_0004_0000_0070),
        icrValue(.{ .destination = 4, .vector = 0x70, .delivery = .fixed }),
    );
}
