// zlint-disable suppressed-errors
const io = @import("../utils/io.zig");
const pci = @import("pci.zig");
const idt = @import("../interrupts/idt.zig");
const vga = @import("vga.zig");
const memory = @import("../memory/memory.zig");

const RTL8139_VENDOR_ID = 0x10EC;
const RTL8139_DEVICE_ID = 0x8139;

const RX_BUFFER_SIZE = 8192 + 16 + 1500;
const TX_BUFFER_SIZE = 1536;
const NUM_TX_DESCRIPTORS = 4;

const Register = enum(u16) {
    MAC0 = 0x00,
    MAC4 = 0x04,
    MAR0 = 0x08,
    MAR4 = 0x0C,
    TxStatus0 = 0x10,
    TxAddr0 = 0x20,
    RxBuf = 0x30,
    ChipCmd = 0x37,
    RxBufPtr = 0x38,
    RxBufAddr = 0x3A,
    IntrMask = 0x3C,
    IntrStatus = 0x3E,
    TxConfig = 0x40,
    RxConfig = 0x44,
    Timer = 0x48,
    RxMissed = 0x4C,
    Cfg9346 = 0x50,
    Config0 = 0x51,
    Config1 = 0x52,
    TimerInt = 0x54,
    MediaStatus = 0x58,
    Config3 = 0x59,
    Config4 = 0x5A,
    HltClk = 0x5B,
    MultiIntr = 0x5C,
    TxSummary = 0x60,
    BasicModeCtrl = 0x62,
    BasicModeStatus = 0x64,
};

const Command = struct {
    const RESET = 0x10;
    const RX_ENABLE = 0x08;
    const TX_ENABLE = 0x04;
};

const InterruptStatus = struct {
    const RX_OK = 0x0001;
    const RX_ERR = 0x0002;
    const TX_OK = 0x0004;
    const TX_ERR = 0x0008;
    const RX_OVERFLOW = 0x0010;
    const RX_UNDERRUN = 0x0020;
    const LINK_CHANGE = 0x0040;
    const RX_FIFO_OVERFLOW = 0x0080;
    const CABLE_LENGTH_CHANGE = 0x2000;
    const TIMEOUT = 0x4000;
    const SYSTEM_ERROR = 0x8000;
};

const RxConfig = struct {
    const AAP = 1 << 0;
    const APM = 1 << 1;
    const AM = 1 << 2;
    const AB = 1 << 3;
    const AR = 1 << 4;
    const AER = 1 << 5;
    const WRAP = 1 << 7;
    const BUFFER_SIZE_8K = 0 << 11;
    const BUFFER_SIZE_16K = 1 << 11;
    const BUFFER_SIZE_32K = 2 << 11;
    const BUFFER_SIZE_64K = 3 << 11;
};

const TxConfig = struct {
    const CLRABT = 1 << 0;
    const TX_RETRY_COUNT = 0 << 4;
    const MAX_DMA_BURST_2048 = 6 << 8;
    const IFG_NORMAL = 3 << 24;
};

const TxStatus = struct {
    const OWN = 1 << 13;
    const TUN = 1 << 14;
    const TOK = 1 << 15;
    const CDH = 1 << 28;
    const OWC = 1 << 29;
    const TABT = 1 << 30;
    const CRS = 1 << 31;
};

var rtl8139_device: ?RTL8139 = null;

const RTL8139 = struct {
    io_base: u16,
    mac_address: [6]u8,
    rx_buffer: [*]u8,
    tx_buffers: [NUM_TX_DESCRIPTORS][*]u8,
    current_tx: u8,
    rx_offset: u16,

    pub fn init(device: pci.PCIDevice) !RTL8139 {
        var rtl = RTL8139{
            .io_base = @intCast(device.bar0 & 0xFFFC),
            // SAFETY: populated by reading MAC registers below
            .mac_address = undefined,
            // SAFETY: assigned from kmalloc allocation below
            .rx_buffer = undefined,
            // SAFETY: each entry assigned from kmalloc in the following loop
            .tx_buffers = undefined,
            .current_tx = 0,
            .rx_offset = 0,
        };

        const rx_mem = memory.kmalloc(RX_BUFFER_SIZE) orelse return error.OutOfMemory;
        rtl.rx_buffer = @ptrCast(@alignCast(rx_mem));

        var i: u8 = 0;
        while (i < NUM_TX_DESCRIPTORS) : (i += 1) {
            const tx_mem = memory.kmalloc(TX_BUFFER_SIZE) orelse return error.OutOfMemory;
            rtl.tx_buffers[i] = @ptrCast(@alignCast(tx_mem));
        }

        const command_reg = pci.readConfig(device.bus, device.device, device.function, 0x04);
        pci.writeConfig(device.bus, device.device, device.function, 0x04, command_reg | 0x04);

        rtl.writeReg8(.Config1, 0x00);

        rtl.writeReg8(.ChipCmd, Command.RESET);
        while ((rtl.readReg8(.ChipCmd) & Command.RESET) != 0) {}

        rtl.writeReg8(.Cfg9346, 0xC0);

        const mac_low = rtl.readReg32(.MAC0);
        const mac_high = rtl.readReg16(.MAC4);
        rtl.mac_address[0] = @intCast(mac_low & 0xFF);
        rtl.mac_address[1] = @intCast((mac_low >> 8) & 0xFF);
        rtl.mac_address[2] = @intCast((mac_low >> 16) & 0xFF);
        rtl.mac_address[3] = @intCast((mac_low >> 24) & 0xFF);
        rtl.mac_address[4] = @intCast(mac_high & 0xFF);
        rtl.mac_address[5] = @intCast((mac_high >> 8) & 0xFF);

        rtl.writeReg32(.RxBuf, @intFromPtr(rtl.rx_buffer));

        i = 0;
        while (i < NUM_TX_DESCRIPTORS) : (i += 1) {
            const tx_addr_reg = @intFromEnum(Register.TxAddr0) + (i * 4);
            rtl.writeReg32(@enumFromInt(tx_addr_reg), @intFromPtr(rtl.tx_buffers[i]));
        }

        rtl.writeReg8(.ChipCmd, Command.RX_ENABLE | Command.TX_ENABLE);

        rtl.writeReg32(.RxConfig, RxConfig.AAP | RxConfig.APM | RxConfig.AM |
            RxConfig.AB | RxConfig.WRAP | RxConfig.BUFFER_SIZE_8K);

        rtl.writeReg32(.TxConfig, TxConfig.IFG_NORMAL | TxConfig.MAX_DMA_BURST_2048);

        rtl.writeReg16(.IntrStatus, 0xFFFF);

        rtl.writeReg16(.IntrMask, InterruptStatus.RX_OK | InterruptStatus.TX_OK |
            InterruptStatus.RX_ERR | InterruptStatus.TX_ERR);

        rtl.writeReg8(.Cfg9346, 0x00);

        return rtl;
    }

    fn readReg8(self: *RTL8139, reg: Register) u8 {
        return io.inb(self.io_base + @intFromEnum(reg));
    }

    fn readReg16(self: *RTL8139, reg: Register) u16 {
        return io.inw(self.io_base + @intFromEnum(reg));
    }

    fn readReg32(self: *RTL8139, reg: Register) u32 {
        return io.inl(self.io_base + @intFromEnum(reg));
    }

    fn writeReg8(self: *RTL8139, reg: Register, value: u8) void {
        io.outb(self.io_base + @intFromEnum(reg), value);
    }

    fn writeReg16(self: *RTL8139, reg: Register, value: u16) void {
        io.outw(self.io_base + @intFromEnum(reg), value);
    }

    fn writeReg32(self: *RTL8139, reg: Register, value: u32) void {
        io.outl(self.io_base + @intFromEnum(reg), value);
    }

    pub fn send(self: *RTL8139, data: []const u8) !void {
        if (data.len > TX_BUFFER_SIZE - 4) {
            return error.PacketTooLarge;
        }

        const tx_status_reg = @intFromEnum(Register.TxStatus0) + (self.current_tx * 4);
        while ((self.readReg32(@enumFromInt(tx_status_reg)) & TxStatus.OWN) == 0) {}

        @memcpy(self.tx_buffers[self.current_tx][0..data.len], data);

        if (data.len < 60) {
            @memset(self.tx_buffers[self.current_tx][data.len..60], 0);
        }

        const tx_len = if (data.len < 60) 60 else data.len;
        self.writeReg32(@enumFromInt(tx_status_reg), tx_len & 0x1FFF);

        self.current_tx = (self.current_tx + 1) % NUM_TX_DESCRIPTORS;
    }

    pub fn receive(self: *RTL8139) ?[]u8 {
        const cmd = self.readReg8(.ChipCmd);
        if ((cmd & 0x01) == 0) {
            return null;
        }

        const header = @as(*align(1) const u16, @ptrCast(&self.rx_buffer[self.rx_offset])).*;
        const status = header;
        const length = @as(*align(1) const u16, @ptrCast(&self.rx_buffer[self.rx_offset + 2])).*;

        if ((status & 0x01) == 0) {
            return null;
        }

        const packet_start = self.rx_offset + 4;
        const packet_data = self.rx_buffer[packet_start .. packet_start + length];

        self.rx_offset = (self.rx_offset + length + 4 + 3) & ~@as(u16, 3);
        if (self.rx_offset > RX_BUFFER_SIZE) {
            self.rx_offset = self.rx_offset % RX_BUFFER_SIZE;
        }

        self.writeReg16(.RxBufPtr, self.rx_offset - 0x10);

        return packet_data;
    }

    pub fn handleInterrupt(self: *RTL8139) void {
        const status = self.readReg16(.IntrStatus);

        if (status & InterruptStatus.RX_OK != 0) {
            while (self.receive()) |packet| {
                const network = @import("../net/network.zig");
                network.handleRxPacket(packet);
            }
        }

        if (status & InterruptStatus.TX_OK != 0) {}

        if (status & InterruptStatus.RX_ERR != 0) {
            vga.print("RTL8139: RX error\n");
        }

        if (status & InterruptStatus.TX_ERR != 0) {
            vga.print("RTL8139: TX error\n");
        }

        self.writeReg16(.IntrStatus, status);
    }
};

pub fn init() void {
    if (pci.findDevice(RTL8139_VENDOR_ID, RTL8139_DEVICE_ID)) |device| {
        vga.print("Found RTL8139 network card\n");

        const rtl = RTL8139.init(device) catch |err| {
            vga.print("Failed to initialize RTL8139: ");
            vga.print(@errorName(err));
            vga.print("\n");
            return;
        };

        rtl8139_device = rtl;

        const irq: u8 = @intCast(pci.readConfig(device.bus, device.device, device.function, 0x3C) & 0xFF);
        idt.register_interrupt_handler(32 + irq, rtl8139InterruptHandler);

        vga.print("RTL8139 initialized - MAC: ");
        for (rtl.mac_address, 0..) |byte, i| {
            const high = byte >> 4;
            const low = byte & 0x0F;
            vga.printChar(if (high < 10) '0' + high else 'A' + high - 10);
            vga.printChar(if (low < 10) '0' + low else 'A' + low - 10);
            if (i < 5) vga.print(":");
        }
        vga.print("\n");
    } else {
        vga.print("RTL8139 network card not found\n");
    }
}

fn rtl8139InterruptHandler(regs: *idt.InterruptRegisters) callconv(.c) void {
    _ = regs;
    if (rtl8139_device) |*rtl| {
        rtl.handleInterrupt();
    }
}

pub fn getMACAddress() ?[6]u8 {
    if (rtl8139_device) |rtl| {
        return rtl.mac_address;
    }
    return null;
}

pub fn isInitialized() bool {
    return rtl8139_device != null;
}

pub fn send(data: []const u8) void {
    if (rtl8139_device) |*device| {
        device.send(data) catch {};
    }
}

pub fn receive() ?[]u8 {
    if (rtl8139_device) |*device| {
        return device.receive();
    }
    return null;
}

pub fn getMacAddress() [6]u8 {
    if (rtl8139_device) |*device| {
        return device.mac_address;
    }
    return [_]u8{0} ** 6;
}

pub fn sendPacket(data: []const u8) !void {
    if (rtl8139_device) |*rtl| {
        try rtl.send(data);
    } else {
        return error.NoDevice;
    }
}

