const io = @import("../utils/io.zig");
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

pub const PCI_CLASS_STORAGE_CONTROLLER: u8 = 0x01;
pub const PCI_SUBCLASS_NVM: u8 = 0x08;
pub const PCI_PROG_IF_NVME: u8 = 0x02;
pub const PCI_CLASS_NETWORK_ADAPTER: u8 = 0x02;
pub const PCI_CLASS_SERIAL_BUS_CONTROLLER: u8 = 0x0C;
pub const PCI_SUBCLASS_USB: u8 = 0x03;
pub const PCI_PROG_IF_XHCI: u8 = 0x30;
pub const PCI_VENDOR_INTEL: u16 = 0x8086;
pub const PCI_DEVICE_INTEL_I225_LM: u16 = 0x15F2;

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
    const vendor_id: u16 = @intCast(vendor_device & 0xFFFF);

    if (vendor_id == 0xFFFF) {
        return null;
    }

    const device_id: u16 = @intCast((vendor_device >> 16) & 0xFFFF);
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

                    if (func == 0) {
                        const header_type = readConfig(@intCast(bus), device, 0, 0x0C);
                        if ((header_type & 0x80) == 0) {
                            break;
                        }
                    }
                }
            }
        }
    }

    return null;
}

pub fn firstDeviceByClass(class_code: u8) ?PCIDevice {
    var bus: u16 = 0;
    while (bus < 256) : (bus += 1) {
        var device: u8 = 0;
        while (device < 32) : (device += 1) {
            var func: u8 = 0;
            while (func < 8) : (func += 1) {
                if (checkDevice(@intCast(bus), device, func)) |pci_device| {
                    if (pci_device.class_code == class_code) {
                        return pci_device;
                    }

                    if (func == 0) {
                        const header_type = readConfig(@intCast(bus), device, 0, 0x0C);
                        if ((header_type & 0x80) == 0) {
                            break;
                        }
                    }
                }
            }
        }
    }

    return null;
}

pub fn firstDeviceByClassSubclassProgIf(class_code: u8, subclass: u8, prog_if: u8) ?PCIDevice {
    var bus: u16 = 0;
    while (bus < 256) : (bus += 1) {
        var device: u8 = 0;
        while (device < 32) : (device += 1) {
            var func: u8 = 0;
            while (func < 8) : (func += 1) {
                if (checkDevice(@intCast(bus), device, func)) |pci_device| {
                    if (matchesClass(pci_device, class_code, subclass, prog_if)) {
                        return pci_device;
                    }

                    if (func == 0) {
                        const header_type = readConfig(@intCast(bus), device, 0, 0x0C);
                        if ((header_type & 0x80) == 0) {
                            break;
                        }
                    }
                }
            }
        }
    }

    return null;
}

pub fn firstNvmeController() ?PCIDevice {
    return firstDeviceByClassSubclassProgIf(PCI_CLASS_STORAGE_CONTROLLER, PCI_SUBCLASS_NVM, PCI_PROG_IF_NVME);
}

pub fn firstIntelI225Lm() ?PCIDevice {
    return findDevice(PCI_VENDOR_INTEL, PCI_DEVICE_INTEL_I225_LM);
}

pub fn firstXhciController() ?PCIDevice {
    return firstDeviceByClassSubclassProgIf(PCI_CLASS_SERIAL_BUS_CONTROLLER, PCI_SUBCLASS_USB, PCI_PROG_IF_XHCI);
}

pub fn matchesClass(device_info: PCIDevice, class_code: u8, subclass: u8, prog_if: u8) bool {
    return device_info.class_code == class_code and
        device_info.subclass == subclass and
        device_info.prog_if == prog_if;
}

pub fn isNvmeController(device_info: PCIDevice) bool {
    return matchesClass(device_info, PCI_CLASS_STORAGE_CONTROLLER, PCI_SUBCLASS_NVM, PCI_PROG_IF_NVME);
}

pub fn isIntelI225Lm(device_info: PCIDevice) bool {
    return device_info.vendor_id == PCI_VENDOR_INTEL and device_info.device_id == PCI_DEVICE_INTEL_I225_LM;
}

pub fn isXhciController(device_info: PCIDevice) bool {
    return matchesClass(device_info, PCI_CLASS_SERIAL_BUS_CONTROLLER, PCI_SUBCLASS_USB, PCI_PROG_IF_XHCI);
}

pub fn stableDeviceId(device_info: PCIDevice) u64 {
    return (@as(u64, device_info.vendor_id) << 32) |
        (@as(u64, device_info.device_id) << 16) |
        (@as(u64, device_info.bus) << 8) |
        (@as(u64, device_info.device) << 3) |
        @as(u64, device_info.function);
}

pub fn findDeviceByStableId(target_device_id: u64) ?PCIDevice {
    var bus: u16 = 0;
    while (bus < 256) : (bus += 1) {
        var device: u8 = 0;
        while (device < 32) : (device += 1) {
            var func: u8 = 0;
            while (func < 8) : (func += 1) {
                if (checkDevice(@intCast(bus), device, func)) |pci_device| {
                    if (stableDeviceId(pci_device) == target_device_id) return pci_device;

                    if (func == 0) {
                        const header_type = readConfig(@intCast(bus), device, 0, 0x0C);
                        if ((header_type & 0x80) == 0) {
                            break;
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

                    if (func == 0) {
                        const header_type = readConfig(@intCast(bus), device, 0, 0x0C) >> 16;
                        if ((header_type & 0x80) == 0) {
                            break;
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

pub fn readConfigByte(bus: u8, device: u8, func: u8, offset: u8) u8 {
    const data = readConfig(bus, device, func, offset);
    const shift: u5 = @intCast((offset & 3) * 8);
    return @as(u8, @truncate(data >> shift));
}

pub fn readConfigWord(bus: u8, device: u8, func: u8, offset: u8) u16 {
    const data = readConfig(bus, device, func, offset);
    const shift: u5 = @intCast((offset & 2) * 8);
    return @as(u16, @truncate(data >> shift));
}

pub fn readConfigDword(bus: u8, device: u8, func: u8, offset: u8) u32 {
    return readConfig(bus, device, func, offset);
}

pub fn writeConfigByte(bus: u8, device: u8, func: u8, offset: u8, value: u8) void {
    const old_data = readConfig(bus, device, func, offset);
    const shift = (offset & 3) * 8;
    const mask = ~(@as(u32, 0xFF) << shift);
    const new_data = (old_data & mask) | (@as(u32, value) << shift);
    writeConfig(bus, device, func, offset, new_data);
}

pub fn writeConfigWord(bus: u8, device: u8, func: u8, offset: u8, value: u16) void {
    const old_data = readConfig(bus, device, func, offset);
    const shift: u5 = @intCast((offset & 2) * 8);
    const mask = ~(@as(u32, 0xFFFF) << shift);
    const new_data = (old_data & mask) | (@as(u32, value) << shift);
    writeConfig(bus, device, func, offset, new_data);
}

fn syntheticPciDevice(vendor_id: u16, device_id: u16, class_code: u8, subclass: u8, prog_if: u8) PCIDevice {
    return .{
        .bus = 0,
        .device = 0,
        .function = 0,
        .vendor_id = vendor_id,
        .device_id = device_id,
        .class_code = class_code,
        .subclass = subclass,
        .prog_if = prog_if,
        .bar0 = 0,
        .bar1 = 0,
        .bar2 = 0,
        .bar3 = 0,
        .bar4 = 0,
        .bar5 = 0,
    };
}

test "PCI helpers identify NVMe controllers" {
    const nvme = syntheticPciDevice(0x144D, 0xA80A, PCI_CLASS_STORAGE_CONTROLLER, PCI_SUBCLASS_NVM, PCI_PROG_IF_NVME);
    try @import("std").testing.expect(isNvmeController(nvme));

    const ahci = syntheticPciDevice(0x8086, 0x2922, PCI_CLASS_STORAGE_CONTROLLER, 0x06, 0x01);
    try @import("std").testing.expect(!isNvmeController(ahci));
}

test "PCI helpers identify Intel I225-LM network controller" {
    const i225_lm = syntheticPciDevice(PCI_VENDOR_INTEL, PCI_DEVICE_INTEL_I225_LM, PCI_CLASS_NETWORK_ADAPTER, 0, 0);
    try @import("std").testing.expect(isIntelI225Lm(i225_lm));

    const e1000 = syntheticPciDevice(PCI_VENDOR_INTEL, 0x100E, PCI_CLASS_NETWORK_ADAPTER, 0, 0);
    try @import("std").testing.expect(!isIntelI225Lm(e1000));
}

test "PCI helpers identify xHCI USB controllers" {
    const xhci = syntheticPciDevice(PCI_VENDOR_INTEL, 0xA0ED, PCI_CLASS_SERIAL_BUS_CONTROLLER, PCI_SUBCLASS_USB, PCI_PROG_IF_XHCI);
    try @import("std").testing.expect(isXhciController(xhci));

    const ehci = syntheticPciDevice(PCI_VENDOR_INTEL, 0x1E26, PCI_CLASS_SERIAL_BUS_CONTROLLER, PCI_SUBCLASS_USB, 0x20);
    try @import("std").testing.expect(!isXhciController(ehci));
}

pub fn writeConfigDword(bus: u8, device: u8, func: u8, offset: u8, value: u32) void {
    writeConfig(bus, device, func, offset, value);
}
