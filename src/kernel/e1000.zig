const std = @import("std");
const pci = @import("pci.zig");
const network = @import("network.zig");
const memory = @import("memory.zig");
const isr = @import("isr.zig");
const vga = @import("vga.zig");
const io = @import("io.zig");

const E1000_VENDOR_ID = 0x8086;
const E1000_DEVICE_IDS = [_]u16{
    0x1000, // 82542
    0x1001, // 82543GC Fiber
    0x1004, // 82543GC Copper
    0x1008, // 82544EI Copper
    0x1009, // 82544EI Fiber
    0x100C, // 82544GC Copper
    0x100D, // 82544GC LOM
    0x100E, // 82540EM
    0x100F, // 82545EM Copper
    0x1010, // 82546EB Copper
    0x1011, // 82545EM Fiber
    0x1012, // 82546EB Fiber
    0x1013, // 82541EI
    0x1014, // 82541ER
    0x1015, // 82540EM LOM
    0x1016, // 82540EP
    0x1017, // 82540EP LOM
    0x1018, // 82541EI Mobile
    0x1019, // 82547EI
    0x101A, // 82547EI Mobile
    0x101D, // 82546EB Copper Quad
    0x101E, // 82540EP LP
    0x1026, // 82545GM Copper
    0x1027, // 82545GM Fiber
    0x1028, // 82545GM SerDes
    0x1049, // 82566MM
    0x104A, // 82566DM
    0x104B, // 82566DC
    0x104C, // 82562V
    0x104D, // 82566MC
    0x105E, // 82571EB Copper
    0x105F, // 82571EB Fiber
    0x1060, // 82571EB SerDes
    0x1075, // 82547GI
    0x1076, // 82541GI
    0x1077, // 82541GI Mobile
    0x1078, // 82541ER
    0x1079, // 82546GB Copper
    0x107A, // 82546GB Fiber
    0x107B, // 82546GB SerDes
    0x107C, // 82541GI LF
    0x107D, // 82572EI Copper
    0x107E, // 82572EI Fiber
    0x107F, // 82572EI SerDes
    0x108A, // 82546GB PCIE
    0x108B, // 82573E
    0x108C, // 82573E IAMT
    0x1096, // 80003ES2LAN Copper
    0x1098, // 80003ES2LAN SerDes
    0x1099, // 82546GB Copper Quad
    0x109A, // 82573L
    0x10A4, // 82571EB Copper Quad
    0x10A7, // 82575EB Copper
    0x10B9, // 82572EI
    0x10BA, // 80003ES2LAN Copper
    0x10BB, // 80003ES2LAN SerDes
    0x10BC, // 82571EB Copper Quad LP
    0x10BD, // 82566DM-2
    0x10BF, // 82567LF
    0x10C0, // 82562V-2
    0x10C2, // 82562G-2
    0x10C3, // 82562GT-2
    0x10C4, // 82562GT
    0x10C5, // 82562G
    0x10C9, // 82576
    0x10CB, // 82567V
    0x10CC, // 82567LM-2
    0x10CD, // 82567LF-2
    0x10CE, // 82567V-2
    0x10D3, // 82574L
    0x10D5, // 82571PT Quad Copper
    0x10D6, // 82575GB Copper
    0x10D9, // 82571EB Dual Copper
    0x10DA, // 82571EB Quad Copper LP
    0x10DE, // 82567LM-3
    0x10DF, // 82567LF-3
    0x10E5, // 82567LM-4
    0x10EA, // 82577LM
    0x10EB, // 82577LC
    0x10EF, // 82578DM
    0x10F0, // 82578DC
    0x10F5, // 82567LM
    0x10F6, // 82574L
    0x1501, // 82567V-3
    0x1502, // 82579LM
    0x1503, // 82579V
    0x150C, // 82583V
    0x150E, // 82580 Copper
    0x150F, // 82580 Fiber
    0x1510, // 82580 SerDes
    0x1511, // 82580 SGMII
    0x1516, // 82580 Copper Dual
    0x1518, // 82576NS
    0x1521, // I350 Copper
    0x1522, // I350 Fiber
    0x1523, // I350 SerDes
    0x1524, // I350 SGMII
    0x1533, // I210 Copper
    0x1536, // I210 Fiber
    0x1537, // I210 SerDes
    0x1538, // I210 SGMII
    0x1539, // I211 Copper
    0x153A, // I217-LM
    0x153B, // I217-V
    0x1559, // I218-V
    0x155A, // I218-LM
    0x156F, // I219-LM
    0x1570, // I219-V
    0x15A0, // I218-LM2
    0x15A1, // I218-V2
    0x15A2, // I218-LM3
    0x15A3, // I218-V3
    0x15B7, // I219-LM2
    0x15B8, // I219-V2
    0x15B9, // I219-LM3
    0x15BB, // I219-LM7
    0x15BC, // I219-V7
    0x15BD, // I219-LM6
    0x15BE, // I219-V6
    0x15D6, // I219-V5
    0x15D7, // I219-LM4
    0x15D8, // I219-V4
    0x15E3, // I219-LM5
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

const StatusBits = struct {
    const FD = 1 << 0;
    const LU = 1 << 1;
    const FUNC_MASK = 3;
    const FUNC_SHIFT = 2;
    const TXOFF = 1 << 4;
    const TBIMODE = 1 << 5;
    const SPEED_MASK = 3;
    const SPEED_SHIFT = 6;
    const ASDV_MASK = 3;
    const ASDV_SHIFT = 8;
    const PCI66 = 1 << 11;
    const BUS64 = 1 << 12;
    const PCIX_MODE = 1 << 13;
    const PCIXSPD_MASK = 3;
    const PCIXSPD_SHIFT = 14;
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
        const ptr = @as(*volatile u32, @ptrFromInt(self.mmio_base + reg));
        return ptr.*;
    }

    fn writeRegister(self: *E1000Device, reg: u32, value: u32) void {
        const ptr = @as(*volatile u32, @ptrFromInt(self.mmio_base + reg));
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
        .mac_addr = undefined,
        .rx_descs = undefined,
        .tx_descs = undefined,
        .rx_buffers = undefined,
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