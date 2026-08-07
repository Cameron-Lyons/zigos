const x86 = @import("../../arch/x86.zig");

const X2APIC_ID_MSR: u32 = 0x802;
const X2APIC_EOI_MSR: u32 = 0x80B;

pub fn localId() u32 {
    return @truncate(x86.readMsr(X2APIC_ID_MSR));
}

pub fn acknowledge() void {
    x86.writeMsr(X2APIC_EOI_MSR, 0);
}
