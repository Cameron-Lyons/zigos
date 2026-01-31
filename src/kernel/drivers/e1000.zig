const pci = @import("pci.zig");
const network = @import("../net/network.zig");
const memory = @import("../memory/memory.zig");
const isr = @import("../interrupts/isr.zig");
const vga = @import("vga.zig");

const E1000_VENDOR_ID = 0x8086;
const E1000_DEVICE_IDS = [_]u16{
    0x1000,
    0x1001,
    0x1004,
    0x1008,
    0x1009,
    0x100C,
    0x100D,
    0x100E,
    0x100F,
    0x1010,
    0x1011,
    0x1012,
    0x1013,
    0x1014,
    0x1015,
    0x1016,
    0x1017,
    0x1018,
    0x1019,
    0x101A,
    0x101D,
    0x101E,
    0x1026,
    0x1027,
    0x1028,
    0x1049,
    0x104A,
    0x104B,
    0x104C,
    0x104D,
    0x105E,
    0x105F,
    0x1060,
    0x1075,
    0x1076,
    0x1077,
    0x1078,
    0x1079,
    0x107A,
    0x107B,
    0x107C,
    0x107D,
    0x107E,
    0x107F,
    0x108A,
    0x108B,
    0x108C,
    0x1096,
    0x1098,
    0x1099,
    0x109A,
    0x10A4,
    0x10A7,
    0x10B9,
    0x10BA,
    0x10BB,
    0x10BC,
    0x10BD,
    0x10BF,
    0x10C0,
    0x10C2,
    0x10C3,
    0x10C4,
    0x10C5,
    0x10C9,
    0x10CB,
    0x10CC,
    0x10CD,
    0x10CE,
    0x10D3,
    0x10D5,
    0x10D6,
    0x10D9,
    0x10DA,
    0x10DE,
    0x10DF,
    0x10E5,
    0x10EA,
    0x10EB,
    0x10EF,
    0x10F0,
    0x10F5,
    0x10F6,
    0x1501,
    0x1502,
    0x1503,
    0x150C,
    0x150E,
    0x150F,
    0x1510,
    0x1511,
    0x1516,
    0x1518,
    0x1521,
    0x1522,
    0x1523,
    0x1524,
    0x1533,
    0x1536,
    0x1537,
    0x1538,
    0x1539,
    0x153A,
    0x153B,
    0x1559,
    0x155A,
    0x156F,
    0x1570,
    0x15A0,
    0x15A1,
    0x15A2,
    0x15A3,
    0x15B7,
    0x15B8,
    0x15B9,
    0x15BB,
    0x15BC,
    0x15BD,
    0x15BE,
    0x15D6,
    0x15D7,
    0x15D8,
    0x15E3,
};

const E1000_NUM_RX_DESC = 32;
const E1000_NUM_TX_DESC = 32;
const RX_BUFFER_SIZE = 2048;
const TX_BUFFER_SIZE = 2048;

const E1000Registers = struct {
    const CTRL = 0x0000;
    const STATUS = 0x0008;
    const EECD = 0x0010;
    const EERD = 0x0014;
    const CTRL_EXT = 0x0018;
    const FLA = 0x001C;
    const MDIC = 0x0020;
    const FCAL = 0x0028;
    const FCAH = 0x002C;
    const FCT = 0x0030;
    const VET = 0x0038;
    const ICR = 0x00C0;
    const ITR = 0x00C4;
    const ICS = 0x00C8;
    const IMS = 0x00D0;
    const IMC = 0x00D8;
    const IAM = 0x00E0;
    const RCTL = 0x0100;
    const FCTTV = 0x0170;
    const TXCW = 0x0178;
    const RXCW = 0x0180;
    const TCTL = 0x0400;
    const TIPG = 0x0410;
    const AIFS = 0x0458;
    const LEDCTL = 0x0E00;
    const PBA = 0x1000;
    const PBS = 0x1008;
    const EEMNGCTL = 0x1010;
    const I2CCMD = 0x1028;
    const FRTIMER = 0x1048;
    const TCPTIMER = 0x104C;
    const RDBAL = 0x2800;
    const RDBAH = 0x2804;
    const RDLEN = 0x2808;
    const RDH = 0x2810;
    const RDT = 0x2818;
    const RDTR = 0x2820;
    const RXDCTL = 0x2828;
    const RADV = 0x282C;
    const TDBAL = 0x3800;
    const TDBAH = 0x3804;
    const TDLEN = 0x3808;
    const TDH = 0x3810;
    const TDT = 0x3818;
    const TIDV = 0x3820;
    const TXDCTL = 0x3828;
    const TADV = 0x382C;
    const RAL = 0x5400;
    const RAH = 0x5404;
    const MTA = 0x5200;
};

const RXDescriptor = packed struct {
    addr: u64,
    length: u16,
    checksum: u16,
    status: u8,
    errors: u8,
    special: u16,
};

const TXDescriptor = packed struct {
    addr: u64,
    length: u16,
    cso: u8,
    cmd: u8,
    status: u8,
    css: u8,
    special: u16,
};

const TXCmd = struct {
    const EOP = 1 << 0;
    const IFCS = 1 << 1;
    const IC = 1 << 2;
    const RS = 1 << 3;
    const RPS = 1 << 4;
    const DEXT = 1 << 5;
    const VLE = 1 << 6;
    const IDE = 1 << 7;
};

const TXStatus = struct {
    const DD = 1 << 0;
    const EC = 1 << 1;
    const LC = 1 << 2;
    const TU = 1 << 3;
};

const RXStatus = struct {
    const DD = 1 << 0;
    const EOP = 1 << 1;
    const IXSM = 1 << 2;
    const VP = 1 << 3;
    const TCPCS = 1 << 5;
    const IPCS = 1 << 6;
    const PIF = 1 << 7;
};

const RCTLBits = struct {
    const EN = 1 << 1;
    const SBP = 1 << 2;
    const UPE = 1 << 3;
    const MPE = 1 << 4;
    const LPE = 1 << 5;
    const LBM_NONE = 0 << 6;
    const LBM_PHY = 3 << 6;
    const RDMTS_HALF = 0 << 8;
    const RDMTS_QUARTER = 1 << 8;
    const RDMTS_EIGHTH = 2 << 8;
    const MO_36 = 0 << 12;
    const MO_35 = 1 << 12;
    const MO_34 = 2 << 12;
    const MO_32 = 3 << 12;
    const BAM = 1 << 15;
    const VFE = 1 << 18;
    const CFIEN = 1 << 19;
    const CFI = 1 << 20;
    const DPF = 1 << 22;
    const PMCF = 1 << 23;
    const SECRC = 1 << 26;
    const BSIZE_256 = 3 << 16;
    const BSIZE_512 = 2 << 16;
    const BSIZE_1024 = 1 << 16;
    const BSIZE_2048 = 0 << 16;
    const BSIZE_4096 = (3 << 16) | (1 << 25);
    const BSIZE_8192 = (2 << 16) | (1 << 25);
    const BSIZE_16384 = (1 << 16) | (1 << 25);
};

const TCTLBits = struct {
    const EN = 1 << 1;
    const PSP = 1 << 3;
    const CT_SHIFT = 4;
    const COLD_SHIFT = 12;
    const SWXOFF = 1 << 22;
    const RTLC = 1 << 24;
};

const CTRLBits = struct {
    const FD = 1 << 0;
    const LRST = 1 << 3;
    const ASDE = 1 << 5;
    const SLU = 1 << 6;
    const ILOS = 1 << 7;
    const SPEED_MASK = 3;
    const SPEED_SHIFT = 8;
    const FRCSPD = 1 << 11;
    const FRCDPLX = 1 << 12;
    const SDP0_DATA = 1 << 18;
    const SDP1_DATA = 1 << 19;
    const ADVD3WUC = 1 << 20;
    const EN_PHY_PWR_MGMT = 1 << 21;
    const SDP0_IODIR = 1 << 22;
    const SDP1_IODIR = 1 << 23;
    const RST = 1 << 26;
    const RFCE = 1 << 27;
    const TFCE = 1 << 28;
    const VME = 1 << 30;
    const PHY_RST = 1 << 31;
};

var e1000_device: ?E1000Device = null;

const E1000Device = struct {
    pci_device: pci.PCIDevice,
    mmio_base: u32,
    mac_addr: [6]u8,
    rx_descs: [*]align(16) RXDescriptor,
    tx_descs: [*]align(16) TXDescriptor,
    rx_buffers: [*]u8,
    tx_buffers: [*]u8,
    rx_cur: u16,
    tx_cur: u16,
    eeprom_exists: bool,

    fn readRegister(self: *E1000Device, reg: u32) u32 {
        const ptr: *volatile u32 = @ptrFromInt(self.mmio_base + reg);
        return ptr.*;
    }

    fn writeRegister(self: *E1000Device, reg: u32, value: u32) void {
        const ptr: *volatile u32 = @ptrFromInt(self.mmio_base + reg);
        ptr.* = value;
    }

    fn detectEEPROM(self: *E1000Device) bool {
        self.writeRegister(E1000Registers.EERD, 1);
        var i: u32 = 0;
        while (i < 1000) : (i += 1) {
            const value = self.readRegister(E1000Registers.EERD);
            if (value & 0x10 != 0) {
                return true;
            }
        }
        return false;
    }

    fn readEEPROM(self: *E1000Device, addr: u16) u16 {
        var data: u32 = 0;
        if (self.eeprom_exists) {
            self.writeRegister(E1000Registers.EERD, (@as(u32, addr) << 8) | 1);
            while ((self.readRegister(E1000Registers.EERD) & 0x10) == 0) {}
            data = self.readRegister(E1000Registers.EERD);
        } else {
            self.writeRegister(E1000Registers.EERD, (@as(u32, addr) << 2) | 1);
            while ((self.readRegister(E1000Registers.EERD) & 0x10) == 0) {}
            data = self.readRegister(E1000Registers.EERD);
        }
        return @as(u16, @truncate(data >> 16));
    }

    fn readMACAddress(self: *E1000Device) void {
        if (self.eeprom_exists) {
            const mac_low = self.readEEPROM(0);
            const mac_mid = self.readEEPROM(1);
            const mac_high = self.readEEPROM(2);
            self.mac_addr[0] = @as(u8, @truncate(mac_low));
            self.mac_addr[1] = @as(u8, @truncate(mac_low >> 8));
            self.mac_addr[2] = @as(u8, @truncate(mac_mid));
            self.mac_addr[3] = @as(u8, @truncate(mac_mid >> 8));
            self.mac_addr[4] = @as(u8, @truncate(mac_high));
            self.mac_addr[5] = @as(u8, @truncate(mac_high >> 8));
        } else {
            const mac_low = self.readRegister(E1000Registers.RAL);
            const mac_high = self.readRegister(E1000Registers.RAH);
            self.mac_addr[0] = @as(u8, @truncate(mac_low));
            self.mac_addr[1] = @as(u8, @truncate(mac_low >> 8));
            self.mac_addr[2] = @as(u8, @truncate(mac_low >> 16));
            self.mac_addr[3] = @as(u8, @truncate(mac_low >> 24));
            self.mac_addr[4] = @as(u8, @truncate(mac_high));
            self.mac_addr[5] = @as(u8, @truncate(mac_high >> 8));
        }
    }

    fn initRX(self: *E1000Device) void {
        const rx_desc_size = @sizeOf(RXDescriptor) * E1000_NUM_RX_DESC;
        const rx_desc_mem = memory.kmalloc(rx_desc_size + 16) orelse unreachable;
        self.rx_descs = @as([*]align(16) RXDescriptor, @ptrCast(@alignCast(rx_desc_mem)));
        const rx_buf_mem = memory.kmalloc(RX_BUFFER_SIZE * E1000_NUM_RX_DESC) orelse unreachable;
        self.rx_buffers = @as([*]u8, @ptrCast(rx_buf_mem));

        for (0..E1000_NUM_RX_DESC) |i| {
            self.rx_descs[i].addr = @intFromPtr(&self.rx_buffers[i * RX_BUFFER_SIZE]);
            self.rx_descs[i].status = 0;
        }

        const rx_desc_addr = @intFromPtr(self.rx_descs);
        self.writeRegister(E1000Registers.RDBAL, @as(u32, @truncate(rx_desc_addr)));
        self.writeRegister(E1000Registers.RDBAH, 0);
        self.writeRegister(E1000Registers.RDLEN, @as(u32, rx_desc_size));
        self.writeRegister(E1000Registers.RDH, 0);
        self.writeRegister(E1000Registers.RDT, E1000_NUM_RX_DESC - 1);

        self.rx_cur = 0;

        self.writeRegister(E1000Registers.RCTL, RCTLBits.EN | RCTLBits.SBP | RCTLBits.UPE | RCTLBits.MPE | RCTLBits.LBM_NONE | RCTLBits.RDMTS_HALF | RCTLBits.BAM | RCTLBits.SECRC | RCTLBits.BSIZE_2048);
    }

    fn initTX(self: *E1000Device) void {
        const tx_desc_size = @sizeOf(TXDescriptor) * E1000_NUM_TX_DESC;
        const tx_desc_mem = memory.kmalloc(tx_desc_size + 16) orelse unreachable;
        self.tx_descs = @as([*]align(16) TXDescriptor, @ptrCast(@alignCast(tx_desc_mem)));
        const tx_buf_mem = memory.kmalloc(TX_BUFFER_SIZE * E1000_NUM_TX_DESC) orelse unreachable;
        self.tx_buffers = @as([*]u8, @ptrCast(tx_buf_mem));

        for (0..E1000_NUM_TX_DESC) |i| {
            self.tx_descs[i].addr = @intFromPtr(&self.tx_buffers[i * TX_BUFFER_SIZE]);
            self.tx_descs[i].cmd = 0;
            self.tx_descs[i].status = TXStatus.DD;
        }

        const tx_desc_addr = @intFromPtr(self.tx_descs);
        self.writeRegister(E1000Registers.TDBAL, @as(u32, @truncate(tx_desc_addr)));
        self.writeRegister(E1000Registers.TDBAH, 0);
        self.writeRegister(E1000Registers.TDLEN, @as(u32, tx_desc_size));
        self.writeRegister(E1000Registers.TDH, 0);
        self.writeRegister(E1000Registers.TDT, 0);

        self.tx_cur = 0;

        self.writeRegister(E1000Registers.TCTL, TCTLBits.EN | TCTLBits.PSP | (15 << TCTLBits.CT_SHIFT) | (64 << TCTLBits.COLD_SHIFT) | TCTLBits.RTLC);
        self.writeRegister(E1000Registers.TIPG, 0x0060200A);
    }

    fn linkUp(self: *E1000Device) void {
        const val = self.readRegister(E1000Registers.CTRL);
        self.writeRegister(E1000Registers.CTRL, val | CTRLBits.SLU);
    }

    fn enableInterrupts(self: *E1000Device) void {
        self.writeRegister(E1000Registers.IMS, 0x1F6DC);
        self.writeRegister(E1000Registers.IMS, 0xFF & ~@as(u32, 4));
        _ = self.readRegister(E1000Registers.ICR);
    }

    pub fn send(self: *E1000Device, data: []const u8) void {
        const cur = self.tx_cur;
        const buf_addr = @intFromPtr(&self.tx_buffers[cur * TX_BUFFER_SIZE]);

        const len = @min(data.len, TX_BUFFER_SIZE);
        @memcpy(@as([*]u8, @ptrFromInt(buf_addr))[0..len], data[0..len]);

        self.tx_descs[cur].length = @as(u16, @intCast(len));
        self.tx_descs[cur].cmd = TXCmd.EOP | TXCmd.IFCS | TXCmd.RS;
        self.tx_descs[cur].status = 0;

        const old_tail = self.readRegister(E1000Registers.TDT);
        self.writeRegister(E1000Registers.TDT, (old_tail + 1) % E1000_NUM_TX_DESC);

        self.tx_cur = (self.tx_cur + 1) % E1000_NUM_TX_DESC;

        while ((self.tx_descs[cur].status & TXStatus.DD) == 0) {}
    }

    pub fn receive(self: *E1000Device) ?[]u8 {
        const cur = self.rx_cur;

        if ((self.rx_descs[cur].status & RXStatus.DD) != 0) {
            if ((self.rx_descs[cur].status & RXStatus.EOP) != 0) {
                const len = self.rx_descs[cur].length;
                const buf_addr = @intFromPtr(&self.rx_buffers[cur * RX_BUFFER_SIZE]);

                self.rx_descs[cur].status = 0;
                const old_tail = self.readRegister(E1000Registers.RDT);
                self.writeRegister(E1000Registers.RDT, (old_tail + 1) % E1000_NUM_RX_DESC);
                self.rx_cur = (self.rx_cur + 1) % E1000_NUM_RX_DESC;

                return @as([*]u8, @ptrFromInt(buf_addr))[0..len];
            }
        }

        return null;
    }
};

fn e1000_interrupt_handler(frame: *isr.InterruptFrame) void {
    _ = frame;
    if (e1000_device) |*dev| {
        const icr = dev.readRegister(E1000Registers.ICR);

        if (icr & 0x80 != 0) {
            while (dev.receive()) |packet| {
                network.processPacket(packet, dev.mac_addr);
            }
        }

        dev.writeRegister(E1000Registers.ICR, icr);
    }
}

pub fn init() void {
    vga.print("Initializing E1000 network driver...\n");

    var bus: u16 = 0;
    while (bus < 256) : (bus += 1) {
        var device: u8 = 0;
        while (device < 32) : (device += 1) {
            var func: u8 = 0;
            while (func < 8) : (func += 1) {
                if (pci.checkDevice(@intCast(bus), device, func)) |pci_device| {
                    if (pci_device.vendor_id == E1000_VENDOR_ID) {
                        for (E1000_DEVICE_IDS) |device_id| {
                            if (pci_device.device_id == device_id) {
                                vga.print("Found E1000 network card!\n");
                                initDevice(pci_device);
                                return;
                            }
                        }
                    }

                    if (func == 0) {
                        const header_type = pci.readConfig(@intCast(bus), device, 0, 0x0C) >> 16;
                        if ((header_type & 0x80) == 0) {
                            break;
                        }
                    }
                }
            }
        }
    }

    vga.print("No E1000 network card found.\n");
}

fn initDevice(pci_device: pci.PCIDevice) void {
    var dev = E1000Device{
        .pci_device = pci_device,
        .mmio_base = 0,
        // SAFETY: populated by readMACAddress call below
        .mac_addr = undefined,
        // SAFETY: initialized in rxInit below
        .rx_descs = undefined,
        // SAFETY: initialized in txInit below
        .tx_descs = undefined,
        // SAFETY: allocated in rxInit below
        .rx_buffers = undefined,
        // SAFETY: allocated in txInit below
        .tx_buffers = undefined,
        .rx_cur = 0,
        .tx_cur = 0,
        .eeprom_exists = false,
    };

    const bar0 = pci.readConfigDword(pci_device.bus, pci_device.device, pci_device.function, 0x10);
    if (bar0 & 1 == 0) {
        dev.mmio_base = bar0 & 0xFFFFFFF0;
    } else {
        vga.print("E1000: BAR0 is I/O space, not supported\n");
        return;
    }

    pci.writeConfigWord(pci_device.bus, pci_device.device, pci_device.function, 0x04, pci.readConfigWord(pci_device.bus, pci_device.device, pci_device.function, 0x04) | 0x06);

    dev.eeprom_exists = dev.detectEEPROM();
    dev.readMACAddress();

    vga.print("E1000 MAC: ");
    for (dev.mac_addr, 0..) |byte, i| {
        const high = byte >> 4;
        const low = byte & 0x0F;
        vga.printChar(if (high < 10) '0' + high else 'A' + high - 10);
        vga.printChar(if (low < 10) '0' + low else 'A' + low - 10);
        if (i < 5) vga.print(":");
    }
    vga.print("\n");

    for (0..0x80) |i| {
        dev.writeRegister(E1000Registers.MTA + @as(u32, @intCast(i * 4)), 0);
    }

    const irq_line = pci.readConfigByte(pci_device.bus, pci_device.device, pci_device.function, 0x3C);
    isr.registerHandler(0x20 + irq_line, e1000_interrupt_handler);

    dev.linkUp();
    dev.initRX();
    dev.initTX();
    dev.enableInterrupts();

    e1000_device = dev;
    network.setNetworkDevice(&e1000NetworkDevice);

    vga.print("E1000 initialized successfully!\n");
}

const e1000NetworkDevice = network.NetworkDevice{
    .send = e1000Send,
    .receive = e1000Receive,
    .getMacAddress = e1000GetMacAddress,
};

fn e1000Send(data: []const u8) void {
    if (e1000_device) |*dev| {
        dev.send(data);
    }
}

fn e1000Receive() ?[]u8 {
    if (e1000_device) |*dev| {
        return dev.receive();
    }
    return null;
}

fn e1000GetMacAddress() [6]u8 {
    if (e1000_device) |*dev| {
        return dev.mac_addr;
    }
    return [_]u8{0} ** 6;
}

pub fn isInitialized() bool {
    return e1000_device != null;
}