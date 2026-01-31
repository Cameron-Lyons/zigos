const pci = @import("pci.zig");
const memory = @import("../memory/memory.zig");
const vga = @import("vga.zig");
const io = @import("../utils/io.zig");
const isr = @import("../interrupts/isr.zig");

const UHCI_CMD: u16 = 0x00;
const UHCI_STS: u16 = 0x02;
const UHCI_INTR: u16 = 0x04;
const UHCI_FRNUM: u16 = 0x06;
const UHCI_FRBASEADD: u16 = 0x08;
const UHCI_SOFMOD: u16 = 0x0C;
const UHCI_PORTSC1: u16 = 0x10;
const UHCI_PORTSC2: u16 = 0x12;

const UHCI_CMD_RS: u16 = 1 << 0;
const UHCI_CMD_HCRESET: u16 = 1 << 1;
const UHCI_CMD_GRESET: u16 = 1 << 2;
const UHCI_CMD_CF: u16 = 1 << 6;
const UHCI_CMD_MAXP: u16 = 1 << 7;

const UHCI_STS_USBINT: u16 = 1 << 0;
const UHCI_STS_ERROR: u16 = 1 << 1;
const UHCI_STS_RD: u16 = 1 << 2;
const UHCI_STS_HSE: u16 = 1 << 3;
const UHCI_STS_HCPE: u16 = 1 << 4;
const UHCI_STS_HCH: u16 = 1 << 5;

const UHCI_PORTSC_CCS: u16 = 1 << 0;
const UHCI_PORTSC_CSC: u16 = 1 << 1;
const UHCI_PORTSC_PE: u16 = 1 << 2;
const UHCI_PORTSC_PRES: u16 = 1 << 12;

const TD_TOKEN_PID_SETUP: u32 = 0x2D;
const TD_TOKEN_PID_IN: u32 = 0x69;
const TD_TOKEN_PID_OUT: u32 = 0xE1;

const TD_CTRL_ACTIVE: u32 = 1 << 23;
const TD_CTRL_STALLED: u32 = 1 << 22;
const TD_CTRL_IOC: u32 = 1 << 24;
const TD_CTRL_CERR_SHIFT: u5 = 27;

const QH_PTR_TERMINATE: u32 = 1 << 0;
const QH_PTR_QH: u32 = 1 << 1;

const FRAME_LIST_SIZE = 1024;
const TD_POOL_SIZE = 128;
const QH_POOL_SIZE = 16;
const MAX_DEVICES = 128;

pub const TransferDescriptor = extern struct {
    link: u32,
    ctrl_status: u32,
    token: u32,
    buffer: u32,
};

pub const QueueHead = extern struct {
    head_link: u32,
    element_link: u32,
};

pub const USBDeviceInfo = struct {
    address: u8,
    max_packet_size: u8,
    port: u8,
    configured: bool,
};

pub const UHCIController = struct {
    pci_device: pci.PCIDevice,
    io_base: u16,
    frame_list: ?[*]u32,
    td_pool: ?[*]TransferDescriptor,
    qh_pool: ?[*]QueueHead,
    td_used: [TD_POOL_SIZE]bool,
    qh_used: [QH_POOL_SIZE]bool,
    devices: [MAX_DEVICES]?USBDeviceInfo,
    next_address: u8,
    irq_line: u8,
    active: bool,
};

var controllers: [4]?UHCIController = [_]?UHCIController{null} ** 4;
var num_controllers: u8 = 0;

pub fn init() void {
    vga.print("Scanning for UHCI controllers...\n");

    var bus: u16 = 0;
    while (bus < 256) : (bus += 1) {
        var device: u8 = 0;
        while (device < 32) : (device += 1) {
            var func: u8 = 0;
            while (func < 8) : (func += 1) {
                if (pci.checkDevice(@intCast(bus), device, func)) |pci_dev| {
                    if (pci_dev.class_code == 0x0C and pci_dev.subclass == 0x03 and pci_dev.prog_if == 0x00) {
                        if (num_controllers < 4) {
                            initController(pci_dev);
                        }
                    }
                }
            }
        }
    }

    if (num_controllers > 0) {
        vga.print("UHCI: Initialized ");
        printNumber(num_controllers);
        vga.print(" controller(s)\n");
    }
}

fn initController(pci_dev: pci.PCIDevice) void {
    const bar4 = pci_dev.bar4;
    const io_base: u16 = @intCast(bar4 & 0xFFFC);

    if (io_base == 0) return;

    const irq_line: u8 = @intCast(pci.readConfigWord(pci_dev.bus, pci_dev.device, pci_dev.function, 0x3C) & 0xFF);

    pci.writeConfigWord(pci_dev.bus, pci_dev.device, pci_dev.function, 0x04, pci.readConfigWord(pci_dev.bus, pci_dev.device, pci_dev.function, 0x04) | 0x05);

    const frame_list_mem = memory.kmalloc(FRAME_LIST_SIZE * 4 + 4096) orelse return;
    const frame_list_addr = (@intFromPtr(frame_list_mem) + 4095) & ~@as(usize, 4095);
    const frame_list: [*]u32 = @ptrFromInt(frame_list_addr);

    for (0..FRAME_LIST_SIZE) |i| {
        frame_list[i] = QH_PTR_TERMINATE;
    }

    const td_mem = memory.kmalloc(@sizeOf(TransferDescriptor) * TD_POOL_SIZE) orelse return;
    const td_pool: [*]TransferDescriptor = @ptrCast(@alignCast(td_mem));

    const qh_mem = memory.kmalloc(@sizeOf(QueueHead) * QH_POOL_SIZE) orelse return;
    const qh_pool: [*]QueueHead = @ptrCast(@alignCast(qh_mem));

    controllers[num_controllers] = UHCIController{
        .pci_device = pci_dev,
        .io_base = io_base,
        .frame_list = frame_list,
        .td_pool = td_pool,
        .qh_pool = qh_pool,
        .td_used = [_]bool{false} ** TD_POOL_SIZE,
        .qh_used = [_]bool{false} ** QH_POOL_SIZE,
        .devices = [_]?USBDeviceInfo{null} ** MAX_DEVICES,
        .next_address = 1,
        .irq_line = irq_line,
        .active = false,
    };

    const ctrl = &controllers[num_controllers].?;
    resetController(ctrl);
    startController(ctrl);
    ctrl.active = true;

    pollPorts(ctrl);

    num_controllers += 1;
}

fn resetController(ctrl: *UHCIController) void {
    io.outw(ctrl.io_base + UHCI_CMD, UHCI_CMD_GRESET);
    busyWait(50000);
    io.outw(ctrl.io_base + UHCI_CMD, 0);
    busyWait(10000);

    io.outw(ctrl.io_base + UHCI_CMD, UHCI_CMD_HCRESET);
    busyWait(10000);

    var timeout: u32 = 100;
    while ((io.inw(ctrl.io_base + UHCI_CMD) & UHCI_CMD_HCRESET) != 0 and timeout > 0) : (timeout -= 1) {
        busyWait(1000);
    }
}

fn startController(ctrl: *UHCIController) void {
    if (ctrl.frame_list) |fl| {
        io.outl(ctrl.io_base + UHCI_FRBASEADD, @intFromPtr(fl));
    }

    io.outw(ctrl.io_base + UHCI_FRNUM, 0);
    io.outb(ctrl.io_base + UHCI_SOFMOD, 64);
    io.outw(ctrl.io_base + UHCI_STS, 0xFFFF);
    io.outw(ctrl.io_base + UHCI_INTR, UHCI_STS_USBINT | UHCI_STS_ERROR | UHCI_STS_RD);
    io.outw(ctrl.io_base + UHCI_CMD, UHCI_CMD_RS | UHCI_CMD_CF | UHCI_CMD_MAXP);
}

pub fn allocTD(ctrl: *UHCIController) ?*TransferDescriptor {
    for (&ctrl.td_used, 0..) |*used, i| {
        if (!used.*) {
            used.* = true;
            if (ctrl.td_pool) |pool| {
                return &pool[i];
            }
        }
    }
    return null;
}

pub fn freeTD(ctrl: *UHCIController, td: *TransferDescriptor) void {
    if (ctrl.td_pool) |pool| {
        const base = @intFromPtr(pool);
        const offset = @intFromPtr(td) - base;
        const index = offset / @sizeOf(TransferDescriptor);
        if (index < TD_POOL_SIZE) {
            ctrl.td_used[index] = false;
        }
    }
}

pub fn allocQH(ctrl: *UHCIController) ?*QueueHead {
    for (&ctrl.qh_used, 0..) |*used, i| {
        if (!used.*) {
            used.* = true;
            if (ctrl.qh_pool) |pool| {
                return &pool[i];
            }
        }
    }
    return null;
}

pub fn freeQH(ctrl: *UHCIController, qh: *QueueHead) void {
    if (ctrl.qh_pool) |pool| {
        const base = @intFromPtr(pool);
        const offset = @intFromPtr(qh) - base;
        const index = offset / @sizeOf(QueueHead);
        if (index < QH_POOL_SIZE) {
            ctrl.qh_used[index] = false;
        }
    }
}

pub fn controlTransfer(ctrl: *UHCIController, device_addr: u8, setup: *const @import("usb.zig").USBSetupPacket, data: ?[]u8) !usize {
    const td_setup = allocTD(ctrl) orelse return error.OutOfResources;
    defer freeTD(ctrl, td_setup);

    const td_status = allocTD(ctrl) orelse return error.OutOfResources;
    defer freeTD(ctrl, td_status);

    var td_data: ?*TransferDescriptor = null;
    if (data != null) {
        td_data = allocTD(ctrl);
    }
    defer if (td_data) |td| freeTD(ctrl, td);

    const qh = allocQH(ctrl) orelse return error.OutOfResources;
    defer freeQH(ctrl, qh);

    td_setup.ctrl_status = TD_CTRL_ACTIVE | (@as(u32, 3) << TD_CTRL_CERR_SHIFT);
    td_setup.token = (@as(u32, @sizeOf(@import("usb.zig").USBSetupPacket) - 1) << 21) |
        (@as(u32, device_addr) << 8) |
        TD_TOKEN_PID_SETUP;
    td_setup.buffer = @intFromPtr(setup);

    if (td_data) |td| {
        td_setup.link = @intFromPtr(td);
        const is_in = (setup.bmRequestType & 0x80) != 0;
        const pid: u32 = if (is_in) TD_TOKEN_PID_IN else TD_TOKEN_PID_OUT;
        const data_buf = data.?;
        td.ctrl_status = TD_CTRL_ACTIVE | (@as(u32, 3) << TD_CTRL_CERR_SHIFT);
        td.token = (@as(u32, @intCast(data_buf.len - 1)) << 21) |
            (@as(u32, 1) << 19) |
            (@as(u32, device_addr) << 8) |
            pid;
        td.buffer = @intFromPtr(data_buf.ptr);
        td.link = @intFromPtr(td_status);
    } else {
        td_setup.link = @intFromPtr(td_status);
    }

    const status_pid: u32 = if (data != null and (setup.bmRequestType & 0x80) != 0) TD_TOKEN_PID_OUT else TD_TOKEN_PID_IN;
    td_status.link = QH_PTR_TERMINATE;
    td_status.ctrl_status = TD_CTRL_ACTIVE | TD_CTRL_IOC | (@as(u32, 3) << TD_CTRL_CERR_SHIFT);
    td_status.token = (0x7FF << 21) |
        (@as(u32, 1) << 19) |
        (@as(u32, device_addr) << 8) |
        status_pid;
    td_status.buffer = 0;

    qh.head_link = QH_PTR_TERMINATE;
    qh.element_link = @intFromPtr(td_setup);

    if (ctrl.frame_list) |fl| {
        fl[0] = @intFromPtr(qh) | QH_PTR_QH;
    }

    var timeout: u32 = 1000;
    while ((td_status.ctrl_status & TD_CTRL_ACTIVE) != 0 and timeout > 0) : (timeout -= 1) {
        busyWait(100);
    }

    if (timeout == 0) return error.Timeout;
    if ((td_status.ctrl_status & TD_CTRL_STALLED) != 0) return error.Stalled;

    const bytes_transferred = if (data) |d| d.len else 0;
    return bytes_transferred;
}

pub fn bulkTransfer(ctrl: *UHCIController, device_addr: u8, endpoint: u8, data: []u8, is_in: bool) !usize {
    const td = allocTD(ctrl) orelse return error.OutOfResources;
    defer freeTD(ctrl, td);

    const qh = allocQH(ctrl) orelse return error.OutOfResources;
    defer freeQH(ctrl, qh);

    const pid: u32 = if (is_in) TD_TOKEN_PID_IN else TD_TOKEN_PID_OUT;
    td.link = QH_PTR_TERMINATE;
    td.ctrl_status = TD_CTRL_ACTIVE | TD_CTRL_IOC | (@as(u32, 3) << TD_CTRL_CERR_SHIFT);
    td.token = (@as(u32, @intCast(data.len - 1)) << 21) |
        (@as(u32, endpoint) << 15) |
        (@as(u32, device_addr) << 8) |
        pid;
    td.buffer = @intFromPtr(data.ptr);

    qh.head_link = QH_PTR_TERMINATE;
    qh.element_link = @intFromPtr(td);

    if (ctrl.frame_list) |fl| {
        fl[0] = @intFromPtr(qh) | QH_PTR_QH;
    }

    var timeout: u32 = 1000;
    while ((td.ctrl_status & TD_CTRL_ACTIVE) != 0 and timeout > 0) : (timeout -= 1) {
        busyWait(100);
    }

    if (timeout == 0) return error.Timeout;
    if ((td.ctrl_status & TD_CTRL_STALLED) != 0) return error.Stalled;

    return data.len;
}

pub fn enumerateDevice(ctrl: *UHCIController, port: u8) ?USBDeviceInfo {
    resetPort(ctrl, port);
    busyWait(100000);

    const setup = @import("usb.zig").USBSetupPacket{
        .bmRequestType = 0x80,
        .bRequest = 0x06,
        .wValue = (0x01 << 8) | 0,
        .wIndex = 0,
        .wLength = 8,
    };

    // SAFETY: filled by the subsequent controlTransfer call
    var desc_buffer: [8]u8 = undefined;
    _ = controlTransfer(ctrl, 0, &setup, desc_buffer[0..]) catch return null;

    const max_packet_size = desc_buffer[7];
    const addr = ctrl.next_address;
    ctrl.next_address += 1;

    const device = USBDeviceInfo{
        .address = addr,
        .max_packet_size = max_packet_size,
        .port = port,
        .configured = false,
    };

    ctrl.devices[addr] = device;
    return device;
}

fn pollPorts(ctrl: *UHCIController) void {
    for (0..2) |port| {
        const port_reg: u16 = if (port == 0) UHCI_PORTSC1 else UHCI_PORTSC2;
        const status = io.inw(ctrl.io_base + port_reg);

        if ((status & UHCI_PORTSC_CCS) != 0) {
            if ((status & UHCI_PORTSC_CSC) != 0) {
                io.outw(ctrl.io_base + port_reg, UHCI_PORTSC_CSC);
            }

            vga.print("UHCI: Device on port ");
            printNumber(@intCast(port));
            vga.print("\n");

            if (enumerateDevice(ctrl, @intCast(port))) |dev| {
                vga.print("UHCI: Enumerated device addr=");
                printNumber(dev.address);
                vga.print(" maxpkt=");
                printNumber(dev.max_packet_size);
                vga.print("\n");
            }
        }
    }
}

fn resetPort(ctrl: *UHCIController, port: u8) void {
    const port_reg: u16 = if (port == 0) UHCI_PORTSC1 else UHCI_PORTSC2;
    io.outw(ctrl.io_base + port_reg, UHCI_PORTSC_PRES);
    busyWait(50000);
    io.outw(ctrl.io_base + port_reg, 0);
    busyWait(10000);
    io.outw(ctrl.io_base + port_reg, UHCI_PORTSC_PE);
    busyWait(10000);
}

pub fn handleInterrupt() void {
    for (&controllers) |*maybe_ctrl| {
        if (maybe_ctrl.*) |*ctrl| {
            if (!ctrl.active) continue;
            const status = io.inw(ctrl.io_base + UHCI_STS);
            if ((status & (UHCI_STS_USBINT | UHCI_STS_ERROR)) != 0) {
                io.outw(ctrl.io_base + UHCI_STS, status);
            }
        }
    }
}

pub fn getController(index: u8) ?*UHCIController {
    if (index < num_controllers) {
        if (controllers[index]) |*ctrl| {
            return ctrl;
        }
    }
    return null;
}

pub fn getNumControllers() u8 {
    return num_controllers;
}

fn busyWait(microseconds: u32) void {
    var i: u32 = 0;
    while (i < microseconds * 10) : (i += 1) {
        asm volatile ("pause");
    }
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
