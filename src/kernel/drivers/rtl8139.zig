// zlint-disable suppressed-errors
const std = @import("std");
const io = @import("../utils/io.zig");
const pci = @import("pci.zig");
const idt = @import("../interrupts/idt.zig");
const console = @import("../utils/console.zig");
const vga = @import("vga.zig");
const memory = @import("../memory/memory.zig");
const network = @import("../net/network.zig");
const ethernet = @import("../net/ethernet.zig");
const arp = @import("../net/arp.zig");
const sync = @import("../utils/sync.zig");

const RTL8139_VENDOR_ID = 0x10EC;
const RTL8139_DEVICE_ID = 0x8139;

const RX_BUFFER_SIZE = 8192 + 16 + 1500;
const TX_BUFFER_SIZE = 1536;
const NUM_TX_DESCRIPTORS = 4;
const RX_POLL_BUFFER_SIZE = 2048;
const PENDING_RX_CAPACITY = 128;

const Register = enum(u16) {
    MAC0 = 0x00,
    MAC4 = 0x04,
    MAR0 = 0x08,
    MAR4 = 0x0C,
    TxStatus0 = 0x10,
    TxStatus1 = 0x14,
    TxStatus2 = 0x18,
    TxStatus3 = 0x1C,
    TxAddr0 = 0x20,
    TxAddr1 = 0x24,
    TxAddr2 = 0x28,
    TxAddr3 = 0x2C,
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

const PendingRx = struct {
    release_offset: u16 = 0,
    ready: bool = false,
};

const RTL8139 = struct {
    io_base: u16,
    mac_address: [6]u8,
    rx_buffer: [*]u8,
    tx_buffers: [NUM_TX_DESCRIPTORS][*]u8,
    rx_lock: sync.SpinLock,
    rx_poll_buffer: [RX_POLL_BUFFER_SIZE]u8,
    current_tx: u8,
    rx_offset: u16,
    pending_rx: [PENDING_RX_CAPACITY]PendingRx,
    pending_queue: [PENDING_RX_CAPACITY]u8,
    pending_free_stack: [PENDING_RX_CAPACITY]u8,
    pending_head: usize,
    pending_tail: usize,
    pending_count: usize,
    pending_free_count: usize,
    testing: bool,
    test_chip_cmd: u8,
    test_intr_status: u16,
    test_rx_buf_ptr: u16,

    pub fn init(device: pci.PCIDevice) !RTL8139 {
        var rtl = RTL8139{
            .io_base = @intCast(device.bar0 & 0xFFFC),
            // SAFETY: populated by reading MAC registers below
            .mac_address = undefined,
            // SAFETY: assigned from kmalloc allocation below
            .rx_buffer = undefined,
            // SAFETY: each entry assigned from kmalloc in the following loop
            .tx_buffers = undefined,
            .rx_lock = sync.SpinLock.init(),
            .rx_poll_buffer = undefined,
            .current_tx = 0,
            .rx_offset = 0,
            .pending_rx = [_]PendingRx{.{}} ** PENDING_RX_CAPACITY,
            .pending_queue = [_]u8{0} ** PENDING_RX_CAPACITY,
            .pending_free_stack = undefined,
            .pending_head = 0,
            .pending_tail = 0,
            .pending_count = 0,
            .pending_free_count = 0,
            .testing = false,
            .test_chip_cmd = 0,
            .test_intr_status = 0,
            .test_rx_buf_ptr = 0,
        };

        initPendingFreeStack(&rtl.pending_free_stack);
        rtl.pending_free_count = rtl.pending_free_stack.len;

        const rx_mem = memory.kmalloc(RX_BUFFER_SIZE) orelse return error.OutOfMemory;
        errdefer memory.kfree(rx_mem);
        rtl.rx_buffer = @ptrCast(@alignCast(rx_mem));

        var i: u8 = 0;
        while (i < NUM_TX_DESCRIPTORS) : (i += 1) {
            const tx_mem = memory.kmalloc(TX_BUFFER_SIZE) orelse {
                var j: u8 = 0;
                while (j < i) : (j += 1) {
                    memory.kfree(@as(*anyopaque, @ptrCast(rtl.tx_buffers[j])));
                }
                return error.OutOfMemory;
            };
            rtl.tx_buffers[i] = @ptrCast(@alignCast(tx_mem));
        }

        const command_reg = pci.readConfig(device.bus, device.device, device.function, 0x04);
        pci.writeConfig(device.bus, device.device, device.function, 0x04, command_reg | 0x05);

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
        if (self.testing) {
            return switch (reg) {
                .ChipCmd => self.test_chip_cmd,
                else => 0,
            };
        }
        return io.inb(self.io_base + @intFromEnum(reg));
    }

    fn readReg16(self: *RTL8139, reg: Register) u16 {
        if (self.testing) {
            return switch (reg) {
                .IntrStatus => self.test_intr_status,
                .RxBufPtr => self.test_rx_buf_ptr,
                else => 0,
            };
        }
        return io.inw(self.io_base + @intFromEnum(reg));
    }

    fn readReg32(self: *RTL8139, reg: Register) u32 {
        return io.inl(self.io_base + @intFromEnum(reg));
    }

    fn writeReg8(self: *RTL8139, reg: Register, value: u8) void {
        if (self.testing) {
            switch (reg) {
                .ChipCmd => self.test_chip_cmd = value,
                else => {},
            }
            return;
        }
        io.outb(self.io_base + @intFromEnum(reg), value);
    }

    fn writeReg16(self: *RTL8139, reg: Register, value: u16) void {
        if (self.testing) {
            switch (reg) {
                .IntrStatus => self.test_intr_status &= ~value,
                .RxBufPtr => self.test_rx_buf_ptr = value,
                else => {},
            }
            return;
        }
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
        const packet = self.claimReceive() orelse return null;
        const copy_len = @min(packet.data.len, self.rx_poll_buffer.len);
        @memcpy(self.rx_poll_buffer[0..copy_len], packet.data[0..copy_len]);
        self.releaseReceived(packet.handle);
        return self.rx_poll_buffer[0..copy_len];
    }

    pub fn claimReceive(self: *RTL8139) ?network.OwnedRxPacket {
        self.rx_lock.acquire();
        defer self.rx_lock.release();

        if (self.pending_free_count == 0) return null;

        const header = @as(*align(1) const u16, @ptrCast(&self.rx_buffer[self.rx_offset])).*;
        const status = header;
        const length = @as(*align(1) const u16, @ptrCast(&self.rx_buffer[self.rx_offset + 2])).*;

        if ((status & 0x01) == 0) {
            return null;
        }

        const packet_start = self.rx_offset + 4;
        if (packet_start + length > RX_BUFFER_SIZE) return null;
        const packet_data = self.rx_buffer[packet_start .. packet_start + length];

        var next_offset = (self.rx_offset + length + 4 + 3) & ~@as(u16, 3);
        if (next_offset > RX_BUFFER_SIZE) {
            next_offset = next_offset % RX_BUFFER_SIZE;
        }

        self.pending_free_count -= 1;
        const handle = self.pending_free_stack[self.pending_free_count];
        self.pending_rx[handle] = .{ .release_offset = next_offset, .ready = false };
        self.pending_queue[self.pending_tail] = handle;
        self.pending_tail = (self.pending_tail + 1) % self.pending_queue.len;
        self.pending_count += 1;
        self.rx_offset = next_offset;

        return .{
            .data = packet_data,
            .mac = self.mac_address,
            .handle = handle,
            .release = releaseClaimedPacket,
        };
    }

    pub fn releaseReceived(self: *RTL8139, handle: usize) void {
        if (handle >= self.pending_rx.len) return;

        self.rx_lock.acquire();
        defer self.rx_lock.release();

        self.pending_rx[handle].ready = true;
        while (self.pending_count != 0) {
            const next_handle = self.pending_queue[self.pending_head];
            const pending = &self.pending_rx[next_handle];
            if (!pending.ready) break;

            self.writeReg16(.RxBufPtr, pending.release_offset -% 0x10);
            pending.* = .{};
            self.pending_head = (self.pending_head + 1) % self.pending_queue.len;
            self.pending_count -= 1;
            self.pending_free_stack[self.pending_free_count] = next_handle;
            self.pending_free_count += 1;
        }
    }

    pub fn handleInterrupt(self: *RTL8139) void {
        const status = self.readReg16(.IntrStatus);

        if (status & InterruptStatus.RX_OK != 0) {
            while (self.claimReceive()) |packet| {
                _ = network.enqueueBorrowedRx(packet);
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

fn initPendingFreeStack(stack: []u8) void {
    var i: usize = 0;
    while (i < stack.len) : (i += 1) {
        stack[i] = @intCast(stack.len - 1 - i);
    }
}

fn releaseClaimedPacket(handle: usize) void {
    if (rtl8139_device) |*rtl| {
        rtl.releaseReceived(handle);
    }
}

pub fn runInterruptSelfTestChecked() bool {
    const rx_mem = memory.kmalloc(RX_BUFFER_SIZE) orelse return false;
    @memset(@as([*]u8, @ptrCast(rx_mem))[0..RX_BUFFER_SIZE], 0);

    var fake = RTL8139{
        .io_base = 0,
        .mac_address = .{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 },
        .rx_buffer = @ptrCast(@alignCast(rx_mem)),
        .tx_buffers = [_][*]u8{@ptrCast(@alignCast(rx_mem))} ** NUM_TX_DESCRIPTORS,
        .rx_lock = sync.SpinLock.init(),
        .rx_poll_buffer = undefined,
        .current_tx = 0,
        .rx_offset = 0,
        .pending_rx = [_]PendingRx{.{}} ** PENDING_RX_CAPACITY,
        .pending_queue = [_]u8{0} ** PENDING_RX_CAPACITY,
        .pending_free_stack = undefined,
        .pending_head = 0,
        .pending_tail = 0,
        .pending_count = 0,
        .pending_free_count = PENDING_RX_CAPACITY,
        .testing = true,
        .test_chip_cmd = 0x00,
        .test_intr_status = InterruptStatus.RX_OK,
        .test_rx_buf_ptr = 0,
    };
    initPendingFreeStack(&fake.pending_free_stack);

    const sender_ip = 0xC0A801F0;
    const target_ip = 0xC0A80102;
    const sender_mac = [6]u8{ 0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x01 };
    const target_mac = fake.mac_address;

    var frame: [ethernet.ETH_HEADER_SIZE + @sizeOf(arp.ARPHeader)]u8 = undefined;
    writeSyntheticArpReply(&frame, sender_ip, target_ip, sender_mac, target_mac);

    const packet_len: u16 = @intCast(frame.len);
    @as(*align(1) u16, @ptrCast(&fake.rx_buffer[0])).* = 0x0001;
    @as(*align(1) u16, @ptrCast(&fake.rx_buffer[2])).* = packet_len;
    @memcpy(fake.rx_buffer[4 .. 4 + frame.len], frame[0..]);

    const previous = rtl8139_device;
    rtl8139_device = fake;
    defer rtl8139_device = previous;
    defer if (rtl8139_device) |*dev| {
        memory.kfree(@as(*anyopaque, @ptrCast(dev.rx_buffer)));
    };

    if (rtl8139_device) |*dev| {
        dev.handleInterrupt();

        const resolved = arp.resolve(sender_ip) orelse return false;
        if (!macEquals(resolved, sender_mac)) return false;

        const expected_release = (((@as(u16, packet_len) + 4 + 3) & ~@as(u16, 3)) -% 0x10);
        return dev.pending_count == 0 and
            dev.pending_free_count == PENDING_RX_CAPACITY and
            dev.test_intr_status == 0 and
            dev.test_rx_buf_ptr == expected_release;
    }

    return false;
}

fn writeSyntheticArpReply(frame: []u8, sender_ip: u32, target_ip: u32, sender_mac: [6]u8, target_mac: [6]u8) void {
    const eth_header: *align(1) ethernet.EthernetHeader = @ptrCast(frame.ptr);
    eth_header.dst_mac0 = target_mac[0];
    eth_header.dst_mac1 = target_mac[1];
    eth_header.dst_mac2 = target_mac[2];
    eth_header.dst_mac3 = target_mac[3];
    eth_header.dst_mac4 = target_mac[4];
    eth_header.dst_mac5 = target_mac[5];
    eth_header.src_mac0 = sender_mac[0];
    eth_header.src_mac1 = sender_mac[1];
    eth_header.src_mac2 = sender_mac[2];
    eth_header.src_mac3 = sender_mac[3];
    eth_header.src_mac4 = sender_mac[4];
    eth_header.src_mac5 = sender_mac[5];
    eth_header.ethertype = @byteSwap(@intFromEnum(ethernet.EtherType.ARP));

    const arp_header: *align(1) arp.ARPHeader = @ptrCast(frame[ethernet.ETH_HEADER_SIZE..].ptr);
    arp_header.hardware_type = @byteSwap(@as(u16, 1));
    arp_header.protocol_type = @byteSwap(@as(u16, 0x0800));
    arp_header.hardware_addr_len = 6;
    arp_header.protocol_addr_len = 4;
    arp_header.opcode = @byteSwap(@as(u16, 2));
    arp_header.sender_mac0 = sender_mac[0];
    arp_header.sender_mac1 = sender_mac[1];
    arp_header.sender_mac2 = sender_mac[2];
    arp_header.sender_mac3 = sender_mac[3];
    arp_header.sender_mac4 = sender_mac[4];
    arp_header.sender_mac5 = sender_mac[5];
    arp_header.sender_ip = @byteSwap(sender_ip);
    arp_header.target_mac0 = target_mac[0];
    arp_header.target_mac1 = target_mac[1];
    arp_header.target_mac2 = target_mac[2];
    arp_header.target_mac3 = target_mac[3];
    arp_header.target_mac4 = target_mac[4];
    arp_header.target_mac5 = target_mac[5];
    arp_header.target_ip = @byteSwap(target_ip);
}

fn macEquals(a: [6]u8, b: [6]u8) bool {
    return a[0] == b[0] and a[1] == b[1] and a[2] == b[2] and a[3] == b[3] and a[4] == b[4] and a[5] == b[5];
}

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
    return getMACAddress() orelse [_]u8{0} ** 6;
}

pub fn sendPacket(data: []const u8) !void {
    if (rtl8139_device) |*rtl| {
        try rtl.send(data);
    } else {
        return error.NoDevice;
    }
}

pub fn debugPrintState(prefix: []const u8) void {
    if (rtl8139_device) |*rtl| {
        const header = @as(*align(1) const u16, @ptrCast(&rtl.rx_buffer[rtl.rx_offset])).*;
        const length = @as(*align(1) const u16, @ptrCast(&rtl.rx_buffer[rtl.rx_offset + 2])).*;
        var line_buf: [192]u8 = undefined;
        const line = std.fmt.bufPrint(
            &line_buf,
            "{s} cmd=0x{x} intr=0x{x} rx_offset=0x{x} hdr=0x{x} len=0x{x} pending={d}/{d}\n",
            .{ prefix, rtl.readReg8(.ChipCmd), rtl.readReg16(.IntrStatus), rtl.rx_offset, header, length, rtl.pending_count, rtl.pending_free_count },
        ) catch return;
        console.print(line);
    } else {
        console.print(prefix);
        console.print(" device=none\n");
    }
}
