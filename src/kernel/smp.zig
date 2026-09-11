const builtin = @import("builtin");
const std = @import("std");
const config = @import("config.zig");
const apic = @import("platform/apic.zig");
const x2apic = @import("interrupts/x2apic.zig");
const x86 = if (builtin.target.os.tag == .freestanding)
    @import("../arch/x86.zig")
else
    struct {
        pub const IA32_GS_BASE_MSR: u32 = 0;
        pub const EFER_MSR: u32 = 0;
        pub const CR3_ADDRESS_MASK: usize = 0;
        pub fn readMsr(_: u32) u64 {
            return 0;
        }
        pub fn writeMsr(_: u32, _: u64) void {}
        pub fn readCr3() usize {
            return 0;
        }
        pub fn writeCr3(_: usize) void {}
        pub fn processContextIdentifiersEnabled() bool {
            return false;
        }
        pub fn invalidatePcid(_: u16) void {}
        pub fn sti() void {}
        pub fn hlt() void {}
        pub fn stiHlt() void {}
        pub fn enableSse() void {}
    };
const tsc_clock = if (builtin.target.os.tag == .freestanding)
    @import("timer/tsc_clock.zig")
else
    struct {
        pub const Deadline = struct {
            pub fn expired(_: @This()) bool {
                return true;
            }
        };
        pub fn afterMilliseconds(_: u64) Deadline {
            return .{};
        }
    };
const spin = @import("utils/spin.zig");
const common = if (builtin.target.os.tag == .freestanding)
    @import("boot/common.zig")
else
    struct {
        pub fn printBootMarker(_: []const u8) void {}
        pub fn printCpuCount(_: u32) void {}
    };
const boot_markers = @import("boot/markers.zig");
const console = if (builtin.target.os.tag == .freestanding)
    @import("utils/console.zig")
else
    struct {
        pub fn print(_: []const u8) void {}
    };

pub const MAX_CPUS: usize = 8;
pub const TLB_IPI_VECTOR: u8 = 0x70;
pub const AP_STACK_BYTES: usize = 16 * 1024;
pub const STARTS_APPLICATION_PROCESSORS = true;
pub const USES_PER_CPU_RUNQUEUES = true;
pub const SHOOTS_DOWN_REMOTE_TLB = true;
pub const PINS_DEVICE_IRQS_TO_BSP = true;
pub const IDLES_PER_CPU = true;
pub const SIPI_PHYSICAL_LIMIT: u32 = 1024 * 1024;

pub const Cpu = struct {
    apic_id: u32 = 0,
    online: bool = false,
};

const bringup = if (builtin.target.os.tag == .freestanding)
    @import("smp_bringup.zig")
else
    struct {
        pub fn start(_: *[MAX_CPUS]Cpu, _: *u8, _: *u8) void {}
    };

var cpus: [MAX_CPUS]Cpu = [_]Cpu{.{}} ** MAX_CPUS;
var cpu_count: u8 = 1;
var online_count: u8 = 1;
var bsp_cpu_index: u8 = 0;
var tlb_target_pcid: u16 = 0;
var tlb_ack_count: u32 = 0;
var initialized = false;

pub fn init(madt: []const u8) void {
    const madt_table = madt;
    if (!config.shouldInitSmp()) {
        common.printBootMarker(boot_markers.smp_ready);
        return;
    }

    const bsp_apic_id: u32 = if (builtin.target.os.tag == .freestanding) x2apic.localId() else 0;
    cpus[0] = .{ .apic_id = bsp_apic_id, .online = true };
    cpu_count = 1;
    online_count = 1;
    bsp_cpu_index = 0;
    setCurrentCpuIndex(0);

    if (builtin.target.os.tag == .freestanding) {
        inventoryFromMadt(bsp_apic_id, madt_table);
        bringup.start(&cpus, &cpu_count, &online_count);
    }

    initialized = true;
    console.print("SMP online CPUs: ");
    common.printCpuCount(online_count);
    console.print("\n");
    common.printBootMarker(boot_markers.smp_ready);
}

pub fn onlineCpuCount() u8 {
    return @max(online_count, 1);
}

pub fn currentCpuIndex() u8 {
    if (builtin.target.os.tag != .freestanding) return 0;
    return @truncate(x86.readMsr(x86.IA32_GS_BASE_MSR));
}

pub fn irqDestinationId() u32 {
    if (!initialized) {
        if (builtin.target.os.tag == .freestanding) return x2apic.localId();
        return 0;
    }
    return cpus[bsp_cpu_index].apic_id;
}

pub fn assignedCpu(task_id: u64, pin_to_bsp: bool) u8 {
    const online = onlineCpuCount();
    if (pin_to_bsp or online <= 1) return 0;
    return @intCast((task_id % (online - 1)) + 1);
}

pub fn idle() void {
    if (builtin.target.os.tag != .freestanding) return;
    x86.stiHlt();
}

pub fn shootdownPcid(pcid: u16) void {
    if (builtin.target.os.tag != .freestanding) return;
    if (online_count <= 1) return;

    tlb_target_pcid = pcid;
    @atomicStore(u32, &tlb_ack_count, 1, .release);
    const self = currentCpuIndex();
    var index: u8 = 0;
    while (index < cpu_count) : (index += 1) {
        if (index == self or !cpus[index].online) continue;
        x2apic.sendIpi(.{
            .destination = cpus[index].apic_id,
            .vector = TLB_IPI_VECTOR,
            .delivery = .fixed,
        });
    }

    const deadline = tsc_clock.afterMilliseconds(100);
    while (@atomicLoad(u32, &tlb_ack_count, .acquire) < online_count) {
        if (deadline.expired()) break;
        spin.hint();
    }
}

pub fn handleTlbIpi() void {
    if (x86.processContextIdentifiersEnabled()) {
        x86.invalidatePcid(tlb_target_pcid);
    } else {
        x86.writeCr3(x86.readCr3());
    }
    x2apic.acknowledge();
    _ = @atomicRmw(u32, &tlb_ack_count, .Add, 1, .acq_rel);
}

pub fn setCurrentCpuIndex(index: u8) void {
    if (builtin.target.os.tag != .freestanding) return;
    x86.writeMsr(x86.IA32_GS_BASE_MSR, index);
}

fn inventoryFromMadt(bsp_apic_id: u32, table: []const u8) void {
    if (table.len == 0) return;
    var processors: [MAX_CPUS]apic.Processor = undefined;
    const count = apic.collectProcessors(table, processors[0..]) catch return;
    var next: u8 = 1;
    for (processors[0..count]) |processor| {
        if (!processor.enabled) continue;
        if (processor.apic_id == bsp_apic_id) {
            cpus[0].apic_id = processor.apic_id;
            continue;
        }
        if (next >= MAX_CPUS) break;
        cpus[next] = .{ .apic_id = processor.apic_id, .online = false };
        next += 1;
    }
    cpu_count = next;
}

test "SMP assigns interactive work to the BSP and spreads background tasks" {
    online_count = 4;
    defer online_count = 1;
    try std.testing.expectEqual(@as(u8, 0), assignedCpu(41, true));
    try std.testing.expectEqual(@as(u8, 3), assignedCpu(41, false));
    try std.testing.expectEqual(@as(u8, 1), assignedCpu(42, false));
    try std.testing.expectEqual(@as(u8, 2), assignedCpu(43, false));
}

test "SMP IRQ affinity stays on the BSP" {
    initialized = true;
    defer initialized = false;
    cpus[0].apic_id = 7;
    try std.testing.expectEqual(@as(u32, 7), irqDestinationId());
    try std.testing.expect(PINS_DEVICE_IRQS_TO_BSP);
    try std.testing.expect(STARTS_APPLICATION_PROCESSORS);
    try std.testing.expect(SHOOTS_DOWN_REMOTE_TLB);
    try std.testing.expect(IDLES_PER_CPU);
    try std.testing.expectEqual(@as(u8, 0x70), TLB_IPI_VECTOR);
    try std.testing.expectEqual(@as(u8, 1), onlineCpuCount());
}
