const pci = @import("pci.zig");
const memory = @import("../memory/memory.zig");
const vga = @import("vga.zig");
const io = @import("../utils/io.zig");
pub const uhci = @import("uhci.zig");

pub const USBSpeed = enum {
    Low,
    Full,
    High,
    Super,
};

pub const USBDeviceDescriptor = extern struct {
    bLength: u8,
    bDescriptorType: u8,
    bcdUSB: u16,
    bDeviceClass: u8,
    bDeviceSubClass: u8,
    bDeviceProtocol: u8,
    bMaxPacketSize0: u8,
    idVendor: u16,
    idProduct: u16,
    bcdDevice: u16,
    iManufacturer: u8,
    iProduct: u8,
    iSerialNumber: u8,
    bNumConfigurations: u8,
};

pub const USBConfigDescriptor = extern struct {
    bLength: u8,
    bDescriptorType: u8,
    wTotalLength: u16,
    bNumInterfaces: u8,
    bConfigurationValue: u8,
    iConfiguration: u8,
    bmAttributes: u8,
    bMaxPower: u8,
};

pub const USBInterfaceDescriptor = extern struct {
    bLength: u8,
    bDescriptorType: u8,
    bInterfaceNumber: u8,
    bAlternateSetting: u8,
    bNumEndpoints: u8,
    bInterfaceClass: u8,
    bInterfaceSubClass: u8,
    bInterfaceProtocol: u8,
    iInterface: u8,
};

pub const USBEndpointDescriptor = extern struct {
    bLength: u8,
    bDescriptorType: u8,
    bEndpointAddress: u8,
    bmAttributes: u8,
    wMaxPacketSize: u16,
    bInterval: u8,
};

pub const USBSetupPacket = extern struct {
    bmRequestType: u8,
    bRequest: u8,
    wValue: u16,
    wIndex: u16,
    wLength: u16,
};

const USB_REQ_GET_DESCRIPTOR = 0x06;
const USB_REQ_SET_ADDRESS = 0x05;
const USB_REQ_SET_CONFIGURATION = 0x09;
const USB_REQ_GET_CONFIGURATION = 0x08;

const USB_DESC_DEVICE = 0x01;
const USB_DESC_CONFIG = 0x02;

const UHCI_CMD = 0x00;
const UHCI_STS = 0x02;
const UHCI_INTR = 0x04;
const UHCI_FRNUM = 0x06;
const UHCI_FRBASEADD = 0x08;
const UHCI_SOFMOD = 0x0C;
const UHCI_PORTSC1 = 0x10;
const UHCI_PORTSC2 = 0x12;

const UHCI_CMD_RS = 1 << 0;
const UHCI_CMD_HCRESET = 1 << 1;
const UHCI_CMD_GRESET = 1 << 2;
const UHCI_CMD_CF = 1 << 6;
const UHCI_CMD_MAXP = 1 << 7;

const UHCI_STS_USBINT = 1 << 0;
const UHCI_STS_ERROR = 1 << 1;
const UHCI_STS_RD = 1 << 2;

const UHCI_PORTSC_CCS = 1 << 0;
const UHCI_PORTSC_CSC = 1 << 1;
const UHCI_PORTSC_PE = 1 << 2;
const UHCI_PORTSC_PRES = 1 << 12;

const TD_TOKEN_PID_SETUP = 0x2D;
const TD_TOKEN_PID_IN = 0x69;
const TD_TOKEN_PID_OUT = 0xE1;

const TD_CTRL_ACTIVE = 1 << 23;
const TD_CTRL_STALLED = 1 << 22;
const TD_CTRL_IOC = 1 << 24;
const TD_CTRL_CERR_SHIFT = 27;

const QH_PTR_TERMINATE = 1 << 0;
const QH_PTR_QH = 1 << 1;

const UHCITransferDescriptor = extern struct {
    link: u32,
    ctrl_status: u32,
    token: u32,
    buffer: u32,
};

const UHCIQueueHead = extern struct {
    head_link: u32,
    element_link: u32,
};

const UHCIController = struct {
    pci_device: pci.PCIDevice,
    io_base: u16,
    frame_list: [*]u32,
    qh_pool: [*]UHCIQueueHead,
    td_pool: [*]UHCITransferDescriptor,
    root_ports: u8,
    devices: [128]?USBDevice,

    fn reset(self: *UHCIController) void {
        io.outw(self.io_base + UHCI_CMD, UHCI_CMD_GRESET);
        busyWait(50000);
        io.outw(self.io_base + UHCI_CMD, 0);
        busyWait(10000);

        io.outw(self.io_base + UHCI_CMD, UHCI_CMD_HCRESET);
        busyWait(10000);

        var timeout: u32 = 100;
        while ((io.inw(self.io_base + UHCI_CMD) & UHCI_CMD_HCRESET) != 0 and timeout > 0) : (timeout -= 1) {
            busyWait(1000);
        }
    }

    fn start(self: *UHCIController) void {
        io.outl(self.io_base + UHCI_FRBASEADD, @intFromPtr(self.frame_list));

        io.outw(self.io_base + UHCI_FRNUM, 0);

        io.outb(self.io_base + UHCI_SOFMOD, 64);

        io.outw(self.io_base + UHCI_STS, 0xFFFF);

        io.outw(self.io_base + UHCI_INTR, UHCI_STS_USBINT | UHCI_STS_ERROR | UHCI_STS_RD);

        io.outw(self.io_base + UHCI_CMD, UHCI_CMD_RS | UHCI_CMD_CF | UHCI_CMD_MAXP);
    }

    fn resetPort(self: *UHCIController, port: u8) void {
        const port_reg: u16 = if (port == 0) UHCI_PORTSC1 else UHCI_PORTSC2;

        io.outw(self.io_base + port_reg, UHCI_PORTSC_PRES);
        busyWait(50000);

        io.outw(self.io_base + port_reg, 0);
        busyWait(10000);

        io.outw(self.io_base + port_reg, UHCI_PORTSC_PE);
        busyWait(10000);
    }

    fn detectDevice(self: *UHCIController, port: u8) bool {
        const port_reg: u16 = if (port == 0) UHCI_PORTSC1 else UHCI_PORTSC2;
        const status = io.inw(self.io_base + port_reg);

        if ((status & UHCI_PORTSC_CCS) != 0) {
            if ((status & UHCI_PORTSC_CSC) != 0) {
                io.outw(self.io_base + port_reg, UHCI_PORTSC_CSC);
            }
            return true;
        }

        return false;
    }

    fn controlTransfer(self: *UHCIController, device: u8, setup: *const USBSetupPacket, data: ?[]u8) !void {
        const td_setup = &self.td_pool[0];
        const td_data = if (data != null) &self.td_pool[1] else null;
        const td_status = &self.td_pool[if (data != null) 2 else 1];

        td_setup.link = if (td_data != null)
            @intFromPtr(td_data) | TD_CTRL_ACTIVE
        else
            @intFromPtr(td_status) | TD_CTRL_ACTIVE;

        td_setup.ctrl_status = TD_CTRL_ACTIVE | (3 << TD_CTRL_CERR_SHIFT);
        td_setup.token = (@as(u32, @sizeOf(USBSetupPacket) - 1) << 21) |
                        (@as(u32, device) << 8) |
                        TD_TOKEN_PID_SETUP;
        td_setup.buffer = @intFromPtr(setup);

        if (td_data) |td| {
            td.link = @intFromPtr(td_status) | TD_CTRL_ACTIVE;
            td.ctrl_status = TD_CTRL_ACTIVE | (3 << TD_CTRL_CERR_SHIFT);

            const pid: u32 = if ((setup.bmRequestType & 0x80) != 0) TD_TOKEN_PID_IN else TD_TOKEN_PID_OUT;
            td.token = (@as(u32, @intCast(data.?.len - 1)) << 21) |
                      (@as(u32, 1) << 19) |
                      (@as(u32, device) << 8) |
                      pid;
            td.buffer = @intFromPtr(data.?.ptr);
        }

        td_status.link = QH_PTR_TERMINATE;
        td_status.ctrl_status = TD_CTRL_ACTIVE | TD_CTRL_IOC | (3 << TD_CTRL_CERR_SHIFT);

        const pid: u32 = if ((setup.bmRequestType & 0x80) != 0) TD_TOKEN_PID_OUT else TD_TOKEN_PID_IN;
        td_status.token = (0x7FF << 21) |
                         (@as(u32, 1) << 19) |
                         (@as(u32, device) << 8) |
                         pid;
        td_status.buffer = 0;

        const qh = &self.qh_pool[0];
        qh.head_link = QH_PTR_TERMINATE;
        qh.element_link = @intFromPtr(td_setup);

        self.frame_list[0] = @intFromPtr(qh) | QH_PTR_QH;

        var timeout: u32 = 1000;
        while ((td_status.ctrl_status & TD_CTRL_ACTIVE) != 0 and timeout > 0) : (timeout -= 1) {
            busyWait(100);
        }

        if (timeout == 0) {
            return error.Timeout;
        }

        if ((td_status.ctrl_status & TD_CTRL_STALLED) != 0) {
            return error.Stalled;
        }
    }
};

const USBDevice = struct {
    address: u8,
    speed: USBSpeed,
    descriptor: USBDeviceDescriptor,
    config: ?USBConfigDescriptor,
    interfaces: [16]?USBInterfaceDescriptor,
    endpoints: [32]?USBEndpointDescriptor,
    driver: ?*anyopaque,
};

var uhci_controllers: [4]?UHCIController = [_]?UHCIController{null} ** 4;
var num_controllers: u8 = 0;
var next_device_address: u8 = 1;

pub fn init() void {
    vga.print("Initializing USB support...\n");

    scanForControllers();

    if (num_controllers > 0) {
        vga.print("Found ");
        printNumber(num_controllers);
        vga.print(" USB controller(s)\n");

        for (uhci_controllers[0..num_controllers]) |*maybe_controller| {
            if (maybe_controller.*) |*controller| {
                initController(controller);
            }
        }
    } else {
        vga.print("No USB controllers found\n");
    }
}

fn scanForControllers() void {
    var bus: u16 = 0;
    while (bus < 256) : (bus += 1) {
        var device: u8 = 0;
        while (device < 32) : (device += 1) {
            var func: u8 = 0;
            while (func < 8) : (func += 1) {
                if (pci.checkDevice(@intCast(bus), device, func)) |pci_device| {
                    if (pci_device.class_code == 0x0C and pci_device.subclass == 0x03) {
                        if (pci_device.prog_if == 0x00) {
                            vga.print("Found UHCI controller\n");
                            if (num_controllers < 4) {
                                addUHCIController(pci_device);
                            }
                        } else if (pci_device.prog_if == 0x10) {
                            vga.print("Found OHCI controller (not supported yet)\n");
                        } else if (pci_device.prog_if == 0x20) {
                            vga.print("Found EHCI controller (not supported yet)\n");
                        } else if (pci_device.prog_if == 0x30) {
                            vga.print("Found xHCI controller (not supported yet)\n");
                        }
                    }
                }
            }
        }
    }
}

fn addUHCIController(pci_device: pci.PCIDevice) void {
    const frame_list_mem = memory.kmalloc(4096 + 16) orelse return;
    const frame_list_addr = (@intFromPtr(frame_list_mem) + 4095) & ~@as(usize, 4095);

    const qh_mem = memory.kmalloc(@sizeOf(UHCIQueueHead) * 64) orelse return;
    const td_mem = memory.kmalloc(@sizeOf(UHCITransferDescriptor) * 128) orelse return;

    uhci_controllers[num_controllers] = UHCIController{
        .pci_device = pci_device,
        .io_base = @as(u16, @intCast(pci_device.bar4 & 0xFFFC)),
        .frame_list = @as([*]u32, @ptrFromInt(frame_list_addr)),
        .qh_pool = @as([*]UHCIQueueHead, @ptrCast(@alignCast(qh_mem))),
        .td_pool = @as([*]UHCITransferDescriptor, @ptrCast(@alignCast(td_mem))),
        .root_ports = 2,
        .devices = [_]?USBDevice{null} ** 128,
    };

    for (0..1024) |i| {
        uhci_controllers[num_controllers].?.frame_list[i] = QH_PTR_TERMINATE;
    }

    num_controllers += 1;
}

fn initController(controller: *UHCIController) void {
    pci.writeConfigWord(controller.pci_device.bus, controller.pci_device.device,
                        controller.pci_device.function, 0x04,
                        pci.readConfigWord(controller.pci_device.bus, controller.pci_device.device,
                                         controller.pci_device.function, 0x04) | 0x05);

    controller.reset();
    controller.start();

    busyWait(100000);

    for (0..controller.root_ports) |port| {
        if (controller.detectDevice(@as(u8, @intCast(port)))) {
            vga.print("USB device detected on port ");
            printNumber(@as(u32, @intCast(port)));
            vga.print("\n");

            controller.resetPort(@as(u8, @intCast(port)));
            enumerateDevice(controller, @as(u8, @intCast(port)));
        }
    }
}

fn enumerateDevice(controller: *UHCIController, port: u8) void {
    _ = port;

    const initial_setup = USBSetupPacket{
        .bmRequestType = 0x80,
        .bRequest = USB_REQ_GET_DESCRIPTOR,
        .wValue = (USB_DESC_DEVICE << 8) | 0,
        .wIndex = 0,
        .wLength = 8,
    };

    // SAFETY: filled by the subsequent controlTransfer call
    var initial_buf: [8]u8 = undefined;
    controller.controlTransfer(0, &initial_setup, initial_buf[0..]) catch {
        vga.print("Failed to get initial device descriptor\n");
        return;
    };

    const addr = next_device_address;
    if (addr >= 128) {
        vga.print("USB: No more device addresses\n");
        return;
    }
    next_device_address += 1;

    const addr_setup = USBSetupPacket{
        .bmRequestType = 0x00,
        .bRequest = USB_REQ_SET_ADDRESS,
        .wValue = addr,
        .wIndex = 0,
        .wLength = 0,
    };

    controller.controlTransfer(0, &addr_setup, null) catch {
        vga.print("Failed to set device address\n");
        return;
    };

    busyWait(20000);

    const desc_setup = USBSetupPacket{
        .bmRequestType = 0x80,
        .bRequest = USB_REQ_GET_DESCRIPTOR,
        .wValue = (USB_DESC_DEVICE << 8) | 0,
        .wIndex = 0,
        .wLength = @sizeOf(USBDeviceDescriptor),
    };

    // SAFETY: filled by the subsequent controlTransfer call
    var desc_buf: [@sizeOf(USBDeviceDescriptor)]u8 = undefined;
    controller.controlTransfer(addr, &desc_setup, desc_buf[0..]) catch {
        vga.print("Failed to get full device descriptor\n");
        return;
    };

    const descriptor: *const USBDeviceDescriptor = @ptrCast(@alignCast(&desc_buf));

    vga.print("USB device: vendor=0x");
    printHex16(@byteSwap(descriptor.idVendor));
    vga.print(" product=0x");
    printHex16(@byteSwap(descriptor.idProduct));
    vga.print(" class=");
    printNumber(descriptor.bDeviceClass);
    vga.print("\n");

    var config_desc: USBConfigDescriptor = undefined;
    if (descriptor.bNumConfigurations > 0) {
        const config_setup = USBSetupPacket{
            .bmRequestType = 0x80,
            .bRequest = USB_REQ_GET_DESCRIPTOR,
            .wValue = (USB_DESC_CONFIG << 8) | 0,
            .wIndex = 0,
            .wLength = @sizeOf(USBConfigDescriptor),
        };

        // SAFETY: filled by the subsequent controlTransfer call
        var config_buf: [@sizeOf(USBConfigDescriptor)]u8 = undefined;
        controller.controlTransfer(addr, &config_setup, config_buf[0..]) catch {
            vga.print("Failed to get config descriptor\n");
            return;
        };

        config_desc = @as(*const USBConfigDescriptor, @ptrCast(@alignCast(&config_buf))).*;

        const set_config = USBSetupPacket{
            .bmRequestType = 0x00,
            .bRequest = USB_REQ_SET_CONFIGURATION,
            .wValue = config_desc.bConfigurationValue,
            .wIndex = 0,
            .wLength = 0,
        };

        controller.controlTransfer(addr, &set_config, null) catch {
            vga.print("Failed to set configuration\n");
            return;
        };
    }

    controller.devices[addr] = USBDevice{
        .address = addr,
        .speed = .Full,
        .descriptor = descriptor.*,
        .config = if (descriptor.bNumConfigurations > 0) config_desc else null,
        .interfaces = [_]?USBInterfaceDescriptor{null} ** 16,
        .endpoints = [_]?USBEndpointDescriptor{null} ** 32,
        .driver = null,
    };

    vga.print("USB device configured at address ");
    printNumber(addr);
    vga.print("\n");
}

fn busyWait(microseconds: u32) void {
    var i: u32 = 0;
    while (i < microseconds * 10) : (i += 1) {
        asm volatile ("pause");
    }
}

fn printHex16(val: u16) void {
    const hex_chars = "0123456789abcdef";
    vga.printChar(hex_chars[(val >> 12) & 0xF]);
    vga.printChar(hex_chars[(val >> 8) & 0xF]);
    vga.printChar(hex_chars[(val >> 4) & 0xF]);
    vga.printChar(hex_chars[val & 0xF]);
}

fn printNumber(num: u32) void {
    if (num == 0) {
        vga.printChar('0');
        return;
    }

    // SAFETY: filled by the following digit extraction loop
    var digits: [10]u8 = undefined;
    var count: usize = 0;
    var n = num;

    while (n > 0) : (n /= 10) {
        digits[count] = @as(u8, @intCast('0' + (n % 10)));
        count += 1;
    }

    var i = count;
    while (i > 0) {
        i -= 1;
        vga.printChar(digits[i]);
    }
}