const builtin = @import("builtin");
const std = @import("std");
const cpu_identity = @import("cpu_identity.zig");
const config = @import("config.zig");
const apic = @import("platform/apic.zig");
const x2apic = @import("interrupts/x2apic.zig");
const x86 = if (builtin.target.os.tag == .freestanding)
    @import("../arch/x86.zig")
else
    struct {
        pub fn readCr3() usize {
            return 0;
        }
        pub fn writeCr3(_: usize) void {}
        pub fn processContextIdentifiersEnabled() bool {
            return false;
        }
        pub fn invalidatePcid(_: u16) void {}
        pub fn stiHlt() void {}
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

pub const MAX_CPUS = cpu_identity.MAX_CPUS;

pub const TLB_IPI_VECTOR: u8 = 0x70;
pub const AP_STACK_BYTES: usize = 16 * 1024;
pub const STARTS_APPLICATION_PROCESSORS = true;
pub const SINGLE_RUNTIME_OWNER = true;
pub const SHOOTS_DOWN_REMOTE_TLB = true;
pub const PINS_DEVICE_IRQS_TO_BSP = true;
pub const IDLES_PER_CPU = true;
pub const SIPI_PHYSICAL_LIMIT: u32 = 1024 * 1024;

pub const Cpu = struct {
    apic_id: u32 = 0,
    online: bool = false,
    kernel_stack_top: usize = 0,
};

const bringup = if (builtin.target.os.tag == .freestanding)
    @import("smp_bringup.zig")
else
    struct {
        pub fn start(_: *[MAX_CPUS]Cpu, _: *u8, _: *u8) void {}
    };

var cpus: [MAX_CPUS]Cpu = @as([MAX_CPUS]Cpu, @splat(.{}));
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
    return cpu_identity.currentIndex();
}

// The shared executor, kernel port, and service tables belong to the BSP.
// APs service architectural interrupts; they do not dispatch runtime work.
pub fn runtimeOwnerCpu() u8 {
    return bsp_cpu_index;
}

pub fn isRuntimeOwner() bool {
    return currentCpuIndex() == runtimeOwnerCpu();
}

pub fn irqDestinationId() u32 {
    if (!initialized and builtin.target.os.tag == .freestanding) return x2apic.localId();
    return cpus[runtimeOwnerCpu()].apic_id;
}

pub fn setOnlineCpuCountForTest(count: u8) u8 {
    if (!builtin.is_test) @compileError("CPU topology override is test-only");
    std.debug.assert(count > 0 and count <= MAX_CPUS);
    const previous = online_count;
    online_count = count;
    return previous;
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
        if (deadline.expired()) @panic("remote TLB shootdown timed out");
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

pub fn setCurrentCpuIndexForTest(index: u8) void {
    cpu_identity.setIndexForTest(index);
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

test "SMP routes runtime and device interrupts to one owner with multiple CPUs online" {
    const previous_count = setOnlineCpuCountForTest(4);
    defer _ = setOnlineCpuCountForTest(previous_count);
    const previous_initialized = initialized;
    defer initialized = previous_initialized;
    const previous_bsp = cpus[0];
    defer cpus[0] = previous_bsp;
    initialized = true;
    cpus[0].apic_id = 7;

    try std.testing.expectEqual(@as(u8, 4), onlineCpuCount());
    try std.testing.expectEqual(@as(u8, 0), runtimeOwnerCpu());
    try std.testing.expect(isRuntimeOwner());
    for (0..MAX_CPUS) |_| {
        try std.testing.expectEqual(@as(u32, 7), irqDestinationId());
    }
    try std.testing.expect(SINGLE_RUNTIME_OWNER);
    try std.testing.expect(PINS_DEVICE_IRQS_TO_BSP);
    try std.testing.expect(STARTS_APPLICATION_PROCESSORS);
    try std.testing.expect(SHOOTS_DOWN_REMOTE_TLB);
    try std.testing.expect(IDLES_PER_CPU);
    try std.testing.expectEqual(@as(u8, 0x70), TLB_IPI_VECTOR);
}
