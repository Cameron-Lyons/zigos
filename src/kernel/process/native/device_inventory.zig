const std = @import("std");
const driver_service = @import("driver_service.zig");

pub const DetectionSource = enum(u8) {
    synthetic,
    ata_bootstrap,
    pci_inventory,
};

pub const DeviceRecord = struct {
    device_class: driver_service.DeviceClass,
    device_id: u64,
    source: DetectionSource,
    detected: bool,
    kernel_bootstrap: bool,
};

var records = defaultRecords();

pub fn reset() void {
    records = defaultRecords();
}

pub fn registerDetected(
    device_class: driver_service.DeviceClass,
    device_id: u64,
    source: DetectionSource,
    kernel_bootstrap: bool,
) void {
    if (device_id == 0) return;

    const record = recordForClassMut(device_class);
    if (record.detected) return;

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

pub fn sourceName(source: DetectionSource) []const u8 {
    return switch (source) {
        .synthetic => "synthetic",
        .ata_bootstrap => "ata_bootstrap",
        .pci_inventory => "pci_inventory",
    };
}

fn defaultRecords() [4]DeviceRecord {
    return .{
        defaultRecord(.network_adapter, 100),
        defaultRecord(.storage_controller, 200),
        defaultRecord(.graphics_adapter, 300),
        defaultRecord(.audio_print_io, 400),
    };
}

fn defaultRecord(device_class: driver_service.DeviceClass, device_id: u64) DeviceRecord {
    return .{
        .device_class = device_class,
        .device_id = device_id,
        .source = .synthetic,
        .detected = false,
        .kernel_bootstrap = false,
    };
}

fn recordForClassMut(device_class: driver_service.DeviceClass) *DeviceRecord {
    return switch (device_class) {
        .network_adapter => &records[0],
        .storage_controller => &records[1],
        .graphics_adapter => &records[2],
        .audio_print_io => &records[3],
    };
}

test "device inventory keeps stable synthetic fallbacks until hardware is discovered" {
    reset();

    const network = recordForClass(.network_adapter);
    const storage = recordForClass(.storage_controller);

    try std.testing.expectEqual(@as(u64, 100), network.device_id);
    try std.testing.expectEqual(@as(u64, 200), storage.device_id);
    try std.testing.expectEqual(DetectionSource.synthetic, network.source);
    try std.testing.expect(!network.detected);
    try std.testing.expect(!storage.kernel_bootstrap);
}

test "device inventory records discovered hardware without overwriting the first handoff record" {
    reset();

    registerDetected(.storage_controller, 0x1F001, .ata_bootstrap, true);
    registerDetected(.network_adapter, 0x8086100E0001, .pci_inventory, false);
    registerDetected(.network_adapter, 0xDEADBEEF, .pci_inventory, false);

    const storage = recordForClass(.storage_controller);
    const network = recordForClass(.network_adapter);

    try std.testing.expectEqual(@as(u64, 0x1F001), storage.device_id);
    try std.testing.expectEqual(DetectionSource.ata_bootstrap, storage.source);
    try std.testing.expect(storage.detected);
    try std.testing.expect(storage.kernel_bootstrap);

    try std.testing.expectEqual(@as(u64, 0x8086100E0001), network.device_id);
    try std.testing.expectEqual(DetectionSource.pci_inventory, network.source);
    try std.testing.expect(network.detected);
    try std.testing.expect(!network.kernel_bootstrap);
}
