const std = @import("std");
const driver_service = @import("driver_service.zig");

pub const DetectionSource = enum(u8) {
    absent,
    synthetic,
    pci_inventory,
    nvme_pci_inventory,
    intel_i225_lm_inventory,
    xhci_inventory,
    platform_policy,
};

pub const Error = error{
    DeviceNotDetected,
    NonProductionDeviceBinding,
};

pub const DeviceRecord = struct {
    device_class: driver_service.DeviceClass,
    device_id: u64,
    source: DetectionSource,
    detected: bool,
    kernel_bootstrap: bool,
};

var records = defaultRecords();

// Modeled-inventory mode: set by the kernel for QEMU "modeled" test boots (e.g.
// the storage-durability proof) where the emulator does not expose the exact
// first-target devices. When enabled, the bootstrap seed may fill in absent
// non-storage device classes so service bootstrap can bring up its drivers,
// while real detected devices (e.g. a QEMU NVMe controller) are left untouched.
// It stays false for the real-hardware ISO build, which keeps strict detection.
var model_device_inventory_enabled = false;

pub fn reset() void {
    records = defaultRecords();
}

pub fn setModelDeviceInventory(enabled: bool) void {
    model_device_inventory_enabled = enabled;
}

pub fn modelDeviceInventoryEnabled() bool {
    return model_device_inventory_enabled;
}

pub fn registerDetected(
    device_class: driver_service.DeviceClass,
    device_id: u64,
    source: DetectionSource,
    kernel_bootstrap: bool,
) void {
    if (device_id == 0) return;
    if (!sourceCanEnterInventory(device_class, source, device_id)) return;

    const record = recordForClassMut(device_class);
    if (record.detected) {
        if (sourceCanBindProductionDriver(record.device_class, record.source, record.device_id) or
            !sourceCanBindProductionDriver(device_class, source, device_id))
        {
            return;
        }
    }

    record.* = .{
        .device_class = device_class,
        .device_id = device_id,
        .source = source,
        .detected = true,
        .kernel_bootstrap = kernel_bootstrap,
    };
}

pub fn recordForClass(device_class: driver_service.DeviceClass) DeviceRecord {
    return recordForClassMut(device_class).*;
}

pub fn deviceIdForClass(device_class: driver_service.DeviceClass) u64 {
    return recordForClass(device_class).device_id;
}

pub fn requireProductionDriverDeviceId(device_class: driver_service.DeviceClass) Error!u64 {
    const record = recordForClass(device_class);
    if (!record.detected) return error.DeviceNotDetected;
    if (!sourceCanBindProductionDriver(device_class, record.source, record.device_id)) return error.NonProductionDeviceBinding;
    return record.device_id;
}

/// Inventory admission follows production-binding policy; modeled test boots
/// seed target-grade records instead of carrying non-production storage sources.
pub fn sourceCanEnterInventory(
    device_class: driver_service.DeviceClass,
    source: DetectionSource,
    device_id: u64,
) bool {
    return sourceCanBindProductionDriver(device_class, source, device_id);
}

pub fn sourceCanBindProductionDriver(
    device_class: driver_service.DeviceClass,
    source: DetectionSource,
    device_id: u64,
) bool {
    if (source == .absent or source == .synthetic or device_id == 0) return false;
    return switch (device_class) {
        .network_adapter => source == .intel_i225_lm_inventory and isStablePciVendorDevice(device_id, PCI_VENDOR_INTEL, PCI_DEVICE_INTEL_I225_LM),
        .storage_controller => source == .nvme_pci_inventory and isStablePciId(device_id),
        .usb_controller => source == .xhci_inventory and isStablePciVendor(device_id, PCI_VENDOR_INTEL),
        .graphics_adapter, .audio_print_io => source == .pci_inventory and isStablePciVendor(device_id, PCI_VENDOR_INTEL),
        .input_device => source == .xhci_inventory and isStablePciVendor(device_id, PCI_VENDOR_INTEL),
        .compositor_policy => source == .platform_policy,
    };
}

pub fn sourceName(source: DetectionSource) []const u8 {
    return switch (source) {
        .absent => "absent",
        .synthetic => "synthetic",
        .pci_inventory => "pci_inventory",
        .nvme_pci_inventory => "nvme_pci_inventory",
        .intel_i225_lm_inventory => "intel_i225_lm_inventory",
        .xhci_inventory => "xhci_inventory",
        .platform_policy => "platform_policy",
    };
}

const PCI_VENDOR_ID_SHIFT = 32;
const PCI_DEVICE_ID_SHIFT = 16;
const PCI_STABLE_ID_COMPONENT_MASK: u64 = 0xFFFF;
const PCI_VENDOR_INTEL: u16 = 0x8086;
const PCI_DEVICE_INTEL_I225_LM: u16 = 0x15F2;

fn stablePciVendor(device_id: u64) u16 {
    return @intCast((device_id >> PCI_VENDOR_ID_SHIFT) & PCI_STABLE_ID_COMPONENT_MASK);
}

fn stablePciDevice(device_id: u64) u16 {
    return @intCast((device_id >> PCI_DEVICE_ID_SHIFT) & PCI_STABLE_ID_COMPONENT_MASK);
}

fn isStablePciVendor(device_id: u64, vendor_id: u16) bool {
    return stablePciVendor(device_id) == vendor_id;
}

fn isStablePciId(device_id: u64) bool {
    return stablePciVendor(device_id) != 0 and stablePciDevice(device_id) != 0;
}

fn isStablePciVendorDevice(device_id: u64, vendor_id: u16, pci_device_id: u16) bool {
    return stablePciVendor(device_id) == vendor_id and stablePciDevice(device_id) == pci_device_id;
}

const device_class_count = std.meta.fields(driver_service.DeviceClass).len;

fn defaultRecords() [device_class_count]DeviceRecord {
    // SAFETY: every slot is written by the inline for below.
    var result: [device_class_count]DeviceRecord = undefined;
    inline for (std.meta.fields(driver_service.DeviceClass)) |field| {
        result[field.value] = defaultRecord(@enumFromInt(field.value));
    }
    return result;
}

fn defaultRecord(device_class: driver_service.DeviceClass) DeviceRecord {
    return .{
        .device_class = device_class,
        .device_id = 0,
        .source = .absent,
        .detected = false,
        .kernel_bootstrap = false,
    };
}

fn recordForClassMut(device_class: driver_service.DeviceClass) *DeviceRecord {
    return &records[@intFromEnum(device_class)];
}

test "device inventory starts absent until hardware is discovered" {
    reset();

    const network = recordForClass(.network_adapter);
    const storage = recordForClass(.storage_controller);
    const usb = recordForClass(.usb_controller);
    const input = recordForClass(.input_device);

    try std.testing.expectEqual(@as(u64, 0), network.device_id);
    try std.testing.expectEqual(@as(u64, 0), storage.device_id);
    try std.testing.expectEqual(@as(u64, 0), usb.device_id);
    try std.testing.expectEqual(@as(u64, 0), input.device_id);
    try std.testing.expectEqual(DetectionSource.absent, network.source);
    try std.testing.expectEqualStrings("absent", sourceName(network.source));
    try std.testing.expect(!network.detected);
    try std.testing.expect(!sourceCanEnterInventory(.network_adapter, network.source, network.device_id));
    try std.testing.expect(!sourceCanBindProductionDriver(.network_adapter, network.source, network.device_id));
    try std.testing.expectError(error.DeviceNotDetected, requireProductionDriverDeviceId(.network_adapter));
    try std.testing.expect(!storage.kernel_bootstrap);
    try std.testing.expect(!usb.kernel_bootstrap);
    try std.testing.expect(!input.kernel_bootstrap);
}

test "device inventory refuses synthetic records for production driver binding" {
    reset();

    registerDetected(.network_adapter, 0x5151, .synthetic, false);
    try std.testing.expect(!recordForClass(.network_adapter).detected);
    try std.testing.expectError(error.DeviceNotDetected, requireProductionDriverDeviceId(.network_adapter));

    registerDetected(.network_adapter, 0x8086_100E_0001, .intel_i225_lm_inventory, false);
    try std.testing.expect(!recordForClass(.network_adapter).detected);
    try std.testing.expectError(error.DeviceNotDetected, requireProductionDriverDeviceId(.network_adapter));

    registerDetected(.network_adapter, 0x8086_15F2_0001, .pci_inventory, false);
    try std.testing.expect(!recordForClass(.network_adapter).detected);
    try std.testing.expectError(error.DeviceNotDetected, requireProductionDriverDeviceId(.network_adapter));

    registerDetected(.network_adapter, 0x8086_15F2_0001, .intel_i225_lm_inventory, false);
    try std.testing.expectEqual(@as(u64, 0x8086_15F2_0001), try requireProductionDriverDeviceId(.network_adapter));
    const network = recordForClass(.network_adapter);
    try std.testing.expect(sourceCanEnterInventory(.network_adapter, network.source, network.device_id));
    try std.testing.expect(sourceCanBindProductionDriver(.network_adapter, network.source, network.device_id));
}

test "device inventory admits only target-grade NVMe for production storage binding" {
    reset();

    registerDetected(.storage_controller, 0x1F001, .nvme_pci_inventory, false);
    try std.testing.expect(!recordForClass(.storage_controller).detected);
    try std.testing.expectError(error.DeviceNotDetected, requireProductionDriverDeviceId(.storage_controller));

    registerDetected(.storage_controller, 0x8086_9A0B_0001, .pci_inventory, false);
    try std.testing.expect(!recordForClass(.storage_controller).detected);
    try std.testing.expectError(error.DeviceNotDetected, requireProductionDriverDeviceId(.storage_controller));

    registerDetected(.storage_controller, 0x8086_9A0B_0001, .nvme_pci_inventory, false);
    try std.testing.expectEqual(@as(u64, 0x8086_9A0B_0001), try requireProductionDriverDeviceId(.storage_controller));
    const storage = recordForClass(.storage_controller);
    try std.testing.expect(sourceCanEnterInventory(.storage_controller, storage.source, storage.device_id));
    try std.testing.expect(sourceCanBindProductionDriver(.storage_controller, storage.source, storage.device_id));
}

test "device inventory only admits xHCI input for production binding" {
    reset();

    registerDetected(.input_device, 0x1234_A0ED_0001, .xhci_inventory, false);
    try std.testing.expect(!recordForClass(.input_device).detected);
    try std.testing.expect(!sourceCanEnterInventory(.input_device, .xhci_inventory, 0x1234_A0ED_0001));
    try std.testing.expect(!sourceCanBindProductionDriver(.input_device, .xhci_inventory, 0x1234_A0ED_0001));
    try std.testing.expectError(error.DeviceNotDetected, requireProductionDriverDeviceId(.input_device));

    registerDetected(.input_device, 0x8086_A0ED_0001, .xhci_inventory, false);
    const input = recordForClass(.input_device);
    try std.testing.expect(input.detected);
    try std.testing.expectEqual(DetectionSource.xhci_inventory, input.source);
    try std.testing.expectEqual(@as(u64, 0x8086_A0ED_0001), try requireProductionDriverDeviceId(.input_device));
}

test "device inventory keeps first target NVMe production binding stable" {
    reset();

    registerDetected(.storage_controller, 0x8086_9A0B_0001, .nvme_pci_inventory, false);
    registerDetected(.storage_controller, 0x8086_9A0B_0002, .nvme_pci_inventory, false);
    const storage = recordForClass(.storage_controller);
    try std.testing.expectEqual(@as(u64, 0x8086_9A0B_0001), storage.device_id);
    try std.testing.expectEqual(DetectionSource.nvme_pci_inventory, storage.source);
    try std.testing.expectEqual(@as(u64, 0x8086_9A0B_0001), try requireProductionDriverDeviceId(.storage_controller));
}

test "device inventory records discovered hardware without overwriting the first handoff record" {
    reset();

    registerDetected(.storage_controller, 0x8086_9A0B_0001, .nvme_pci_inventory, false);
    registerDetected(.network_adapter, 0x8086_15F2_0001, .intel_i225_lm_inventory, false);
    registerDetected(.network_adapter, 0xDEAD_BEEF, .intel_i225_lm_inventory, false);
    registerDetected(.usb_controller, 0x8086_A0ED_0001, .xhci_inventory, false);
    registerDetected(.input_device, 0x8086_A0ED_0001, .xhci_inventory, false);
    registerDetected(.compositor_policy, 0xC0DE_9001, .platform_policy, false);

    const storage = recordForClass(.storage_controller);
    const network = recordForClass(.network_adapter);
    const usb = recordForClass(.usb_controller);
    const input = recordForClass(.input_device);
    const compositor_policy = recordForClass(.compositor_policy);

    try std.testing.expectEqual(@as(u64, 0x8086_9A0B_0001), storage.device_id);
    try std.testing.expectEqual(DetectionSource.nvme_pci_inventory, storage.source);
    try std.testing.expect(storage.detected);
    try std.testing.expect(!storage.kernel_bootstrap);
    try std.testing.expect(sourceCanEnterInventory(.storage_controller, storage.source, storage.device_id));
    try std.testing.expect(sourceCanBindProductionDriver(.storage_controller, storage.source, storage.device_id));
    try std.testing.expectEqual(@as(u64, 0x8086_9A0B_0001), try requireProductionDriverDeviceId(.storage_controller));

    try std.testing.expectEqual(@as(u64, 0x8086_15F2_0001), network.device_id);
    try std.testing.expectEqual(DetectionSource.intel_i225_lm_inventory, network.source);
    try std.testing.expect(network.detected);
    try std.testing.expect(!network.kernel_bootstrap);
    try std.testing.expectEqual(@as(u64, 0x8086_15F2_0001), try requireProductionDriverDeviceId(.network_adapter));

    try std.testing.expectEqual(@as(u64, 0x8086_A0ED_0001), usb.device_id);
    try std.testing.expectEqual(DetectionSource.xhci_inventory, usb.source);
    try std.testing.expect(usb.detected);
    try std.testing.expect(!usb.kernel_bootstrap);
    try std.testing.expectEqual(@as(u64, 0x8086_A0ED_0001), try requireProductionDriverDeviceId(.usb_controller));

    try std.testing.expectEqual(@as(u64, 0x8086_A0ED_0001), input.device_id);
    try std.testing.expectEqual(DetectionSource.xhci_inventory, input.source);
    try std.testing.expect(input.detected);
    try std.testing.expect(!input.kernel_bootstrap);
    try std.testing.expectEqual(@as(u64, 0x8086_A0ED_0001), try requireProductionDriverDeviceId(.input_device));

    try std.testing.expectEqual(@as(u64, 0xC0DE_9001), compositor_policy.device_id);
    try std.testing.expectEqual(DetectionSource.platform_policy, compositor_policy.source);
    try std.testing.expect(compositor_policy.detected);
    try std.testing.expectEqual(@as(u64, 0xC0DE_9001), try requireProductionDriverDeviceId(.compositor_policy));
}
