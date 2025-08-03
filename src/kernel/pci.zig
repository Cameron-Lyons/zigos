const std = @import("std");
const io = @import("io.zig");
const vga = @import("vga.zig");

const CONFIG_ADDRESS = 0xCF8;
const CONFIG_DATA = 0xCFC;

pub const PCIDevice = struct {
    bus: u8,
    device: u8,
    function: u8,
    vendor_id: u16,
    device_id: u16,
    class_code: u8,
    subclass: u8,
    prog_if: u8,
    bar0: u32,
    bar1: u32,
    bar2: u32,
    bar3: u32,
    bar4: u32,
    bar5: u32,
};

pub fn readConfig(bus: u8, device: u8, func: u8, offset: u8) u32 {
    const address = @as(u32, 0x80000000) |
                   (@as(u32, bus) << 16) |
                   (@as(u32, device) << 11) |
                   (@as(u32, func) << 8) |
                   (@as(u32, offset) & 0xFC);
    
    io.outl(CONFIG_ADDRESS, address);
    return io.inl(CONFIG_DATA);
}

pub fn writeConfig(bus: u8, device: u8, func: u8, offset: u8, value: u32) void {
    const address = @as(u32, 0x80000000) |
                   (@as(u32, bus) << 16) |
                   (@as(u32, device) << 11) |
                   (@as(u32, func) << 8) |
                   (@as(u32, offset) & 0xFC);
    
    io.outl(CONFIG_ADDRESS, address);
    io.outl(CONFIG_DATA, value);
}

pub fn checkDevice(bus: u8, device: u8, func: u8) ?PCIDevice {
    const vendor_device = readConfig(bus, device, func, 0x00);
    const vendor_id = @as(u16, @intCast(vendor_device & 0xFFFF));
    
    if (vendor_id == 0xFFFF) {
        return null;
    }
    
    const device_id = @as(u16, @intCast((vendor_device >> 16) & 0xFFFF));
    const class_info = readConfig(bus, device, func, 0x08);
    
    const pci_device = PCIDevice{
        .bus = bus,
        .device = device,
        .function = func,
        .vendor_id = vendor_id,
        .device_id = device_id,
        .class_code = @intCast((class_info >> 24) & 0xFF),
        .subclass = @intCast((class_info >> 16) & 0xFF),
        .prog_if = @intCast((class_info >> 8) & 0xFF),
        .bar0 = readConfig(bus, device, func, 0x10),
        .bar1 = readConfig(bus, device, func, 0x14),
        .bar2 = readConfig(bus, device, func, 0x18),
        .bar3 = readConfig(bus, device, func, 0x1C),
        .bar4 = readConfig(bus, device, func, 0x20),
        .bar5 = readConfig(bus, device, func, 0x24),
    };
    
    return pci_device;
}

pub fn findDevice(vendor_id: u16, device_id: u16) ?PCIDevice {
    var bus: u16 = 0;
    while (bus < 256) : (bus += 1) {
        var device: u8 = 0;
        while (device < 32) : (device += 1) {
            var func: u8 = 0;
            while (func < 8) : (func += 1) {
                if (checkDevice(@intCast(bus), device, func)) |pci_device| {
                    if (pci_device.vendor_id == vendor_id and pci_device.device_id == device_id) {
                        return pci_device;
                    }
                    
                    // Check if this is a multi-function device
                    if (func == 0) {
                        const header_type = readConfig(@intCast(bus), device, 0, 0x0C);
                        if ((header_type & 0x80) == 0) {
                            break; // Single function device
                        }
                    }
                }
            }
        }
    }
    
    return null;
}

pub fn scanBus() void {
    vga.print("Scanning PCI bus...\n");
    
    var bus: u16 = 0;
    while (bus < 256) : (bus += 1) {
        var device: u8 = 0;
        while (device < 32) : (device += 1) {
            var func: u8 = 0;
            while (func < 8) : (func += 1) {
                if (checkDevice(@intCast(bus), device, func)) |pci_device| {
                    vga.print("PCI ");
                    printHex8(@intCast(bus));
                    vga.print(":");
                    printHex8(device);
                    vga.print(".");
                    printHex8(func);
                    vga.print(" - Vendor: ");
                    printHex16(pci_device.vendor_id);
                    vga.print(" Device: ");
                    printHex16(pci_device.device_id);
                    vga.print(" Class: ");
                    printHex8(pci_device.class_code);
                    vga.print(":");
                    printHex8(pci_device.subclass);
                    vga.print("\n");
                    
                    // Check if this is a multi-function device
                    if (func == 0) {
                        const header_type = readConfig(@intCast(bus), device, 0, 0x0C) >> 16;
                        if ((header_type & 0x80) == 0) {
                            break; // Single function device
                        }
                    }
                }
            }
        }
    }
}

fn printHex8(value: u8) void {
    const high = value >> 4;
    const low = value & 0x0F;
    vga.printChar(if (high < 10) '0' + high else 'A' + high - 10);
    vga.printChar(if (low < 10) '0' + low else 'A' + low - 10);
}

fn printHex16(value: u16) void {
    printHex8(@intCast((value >> 8) & 0xFF));
    printHex8(@intCast(value & 0xFF));
}