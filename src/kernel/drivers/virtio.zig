// zlint-disable suppressed-errors
const std = @import("std");
const pci = @import("pci.zig");
const memory = @import("../memory/memory.zig");
const paging = @import("../memory/paging.zig");
const vga = @import("vga.zig");
const isr = @import("../interrupts/isr.zig");
const ethernet = @import("../net/ethernet.zig");
const arp = @import("../net/arp.zig");
const network = @import("../net/network.zig");
const sync = @import("../utils/sync.zig");

const VIRTIO_VENDOR_ID = 0x1AF4;
const VIRTIO_NET_DEVICE_ID = 0x1000;
const VIRTIO_NET_MODERN_ID = 0x1041;

const VIRTIO_PCI_CAP_COMMON_CFG = 1;
const VIRTIO_PCI_CAP_NOTIFY_CFG = 2;
const VIRTIO_PCI_CAP_ISR_CFG = 3;
const VIRTIO_PCI_CAP_DEVICE_CFG = 4;

const VIRTIO_NET_F_MAC = 1 << 5;
const VIRTIO_NET_F_STATUS = 1 << 16;

const VIRTIO_STATUS_RESET = 0;
const VIRTIO_STATUS_ACKNOWLEDGE = 1;
const VIRTIO_STATUS_DRIVER = 2;
const VIRTIO_STATUS_FEATURES_OK = 8;
const VIRTIO_STATUS_DRIVER_OK = 4;

const VIRTQ_DESC_F_WRITE = 2;
const VIRTQUEUE_SIZE: u16 = 256;
const VIRTIO_BUFFER_SIZE: usize = 2048;
const VIRTIO_NET_HEADER_SIZE: usize = 10;

const VirtqDesc = extern struct {
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
};

const VirtqAvail = extern struct {
    flags: u16,
    idx: u16,
    ring: [256]u16,
    used_event: u16,
};

const VirtqUsedElem = extern struct {
    id: u32,
    len: u32,
};

const VirtqUsed = extern struct {
    flags: u16,
    idx: u16,
    ring: [256]VirtqUsedElem,
    avail_event: u16,
};

const Virtqueue = struct {
    num: u16,
    desc: [*]VirtqDesc,
    avail: *VirtqAvail,
    used: *VirtqUsed,
    notify_off: u16,
    last_used_idx: u16,
    free_head: u16,
    num_free: u16,
    desc_state: [256]DescState,

    const DescState = struct {
        data: ?*anyopaque,
        len: u32,
        next: u16,
    };
};

const VirtioNetConfig = extern struct {
    mac: [6]u8,
    status: u16,
    max_virtqueue_pairs: u16,
    mtu: u16,
    speed: u32,
    duplex: u8,
};

const VirtioNetHeader = extern struct {
    flags: u8,
    gso_type: u8,
    hdr_len: u16,
    gso_size: u16,
    csum_start: u16,
    csum_offset: u16,
    num_buffers: u16,
};

const VirtioCommonCfg = extern struct {
    device_feature_select: u32,
    device_feature: u32,
    driver_feature_select: u32,
    driver_feature: u32,
    config_msix_vector: u16,
    num_queues: u16,
    device_status: u8,
    config_generation: u8,
    queue_select: u16,
    queue_size: u16,
    queue_msix_vector: u16,
    queue_enable: u16,
    queue_notify_off: u16,
    queue_desc: u64,
    queue_driver: u64,
    queue_device: u64,
};

const VirtioNetDevice = struct {
    pci_device: pci.PCIDevice,
    common_cfg: *align(1) volatile VirtioCommonCfg,
    device_cfg: *align(1) VirtioNetConfig,
    notify_base: usize,
    notify_off_multiplier: u32,
    isr_cfg: *align(1) volatile u8,
    mac_addr: [6]u8,
    rx_queue: Virtqueue,
    tx_queue: Virtqueue,
    rx_buffers: [*]u8,
    tx_buffers: [*]u8,
    rx_lock: sync.SpinLock,
    rx_poll_buffer: [VIRTIO_BUFFER_SIZE]u8,

    fn commonFieldPtr(self: *VirtioNetDevice, comptime T: type, comptime field: []const u8) *align(1) volatile T {
        return @ptrFromInt(@intFromPtr(self.common_cfg) + @offsetOf(VirtioCommonCfg, field));
    }

    fn deviceFieldPtr(self: *VirtioNetDevice, comptime T: type, comptime field: []const u8) *align(1) T {
        return @ptrFromInt(@intFromPtr(self.device_cfg) + @offsetOf(VirtioNetConfig, field));
    }

    fn readFeatures(self: *VirtioNetDevice) u64 {
        self.commonFieldPtr(u32, "device_feature_select").* = 0;
        const low = self.commonFieldPtr(u32, "device_feature").*;
        self.commonFieldPtr(u32, "device_feature_select").* = 1;
        const high = self.commonFieldPtr(u32, "device_feature").*;
        return (@as(u64, high) << 32) | low;
    }

    fn writeFeatures(self: *VirtioNetDevice, features: u64) void {
        self.commonFieldPtr(u32, "driver_feature_select").* = 0;
        self.commonFieldPtr(u32, "driver_feature").* = @as(u32, @truncate(features));
        self.commonFieldPtr(u32, "driver_feature_select").* = 1;
        self.commonFieldPtr(u32, "driver_feature").* = @as(u32, @truncate(features >> 32));
    }

    fn setupQueue(self: *VirtioNetDevice, queue: *Virtqueue, index: u16, size: u16) !void {
        queue.num = size;

        const desc_size = @sizeOf(VirtqDesc) * size;
        const avail_size = @sizeOf(VirtqAvail);
        const used_size = @sizeOf(VirtqUsed);
        const used_offset = std.mem.alignForward(usize, desc_size + avail_size, @alignOf(VirtqUsed));
        const total_size = used_offset + used_size;

        const queue_mem = memory.kmalloc(total_size + 4096) orelse return error.OutOfMemory;
        const queue_addr = (@intFromPtr(queue_mem) + 4095) & ~@as(usize, 4095);

        queue.desc = @as([*]VirtqDesc, @ptrFromInt(queue_addr));
        queue.avail = @as(*VirtqAvail, @ptrFromInt(queue_addr + desc_size));
        queue.used = @as(*VirtqUsed, @ptrFromInt(queue_addr + used_offset));

        @memset(@as([*]u8, @ptrFromInt(queue_addr))[0..total_size], 0);

        for (0..size) |i| {
            queue.desc[i].next = @as(u16, @intCast((i + 1) % size));
            queue.desc_state[i] = .{ .data = null, .len = 0, .next = 0 };
        }
        queue.free_head = 0;
        queue.num_free = size;
        queue.last_used_idx = 0;

        self.commonFieldPtr(u16, "queue_select").* = index;
        queue.notify_off = self.commonFieldPtr(u16, "queue_notify_off").*;
        self.commonFieldPtr(u16, "queue_size").* = size;
        self.commonFieldPtr(u64, "queue_desc").* = queue_addr;
        self.commonFieldPtr(u64, "queue_driver").* = queue_addr + desc_size;
        self.commonFieldPtr(u64, "queue_device").* = queue_addr + used_offset;
        self.commonFieldPtr(u16, "queue_enable").* = 1;
    }

    fn addBuffer(_: *VirtioNetDevice, queue: *Virtqueue, data: []const u8, writable: bool) !u16 {
        if (queue.num_free == 0) return error.QueueFull;

        const desc_idx = queue.free_head;
        const desc = &queue.desc[desc_idx];

        desc.addr = @intFromPtr(data.ptr);
        desc.len = @as(u32, @intCast(data.len));
        desc.flags = if (writable) VIRTQ_DESC_F_WRITE else 0;

        queue.free_head = desc.next;
        queue.num_free -= 1;

        queue.desc_state[desc_idx] = .{
            .data = @as(*anyopaque, @ptrFromInt(@intFromPtr(data.ptr))),
            .len = @as(u32, @intCast(data.len)),
            .next = 0,
        };

        const avail_idx = queue.avail.idx;
        queue.avail.ring[avail_idx % queue.num] = desc_idx;

        asm volatile ("" ::: .{ .memory = true });

        queue.avail.idx = avail_idx +% 1;

        asm volatile ("" ::: .{ .memory = true });

        return desc_idx;
    }

    fn notify(self: *VirtioNetDevice, queue: *Virtqueue, queue_index: u16) void {
        const notify_addr = self.notify_base +
            @as(usize, queue.notify_off) * self.notify_off_multiplier;
        const notify_ptr: *align(1) volatile u16 = @ptrFromInt(notify_addr);
        notify_ptr.* = queue_index;
    }

    fn processUsedBuffers(_: *VirtioNetDevice, queue: *Virtqueue) void {
        while (queue.last_used_idx != queue.used.idx) {
            const used_elem = &queue.used.ring[queue.last_used_idx % queue.num];
            const desc_idx: u16 = @truncate(used_elem.id);

            queue.desc[desc_idx].next = queue.free_head;
            queue.free_head = desc_idx;
            queue.num_free += 1;

            queue.last_used_idx +%= 1;
        }
    }

    pub fn send(self: *VirtioNetDevice, packet: []const u8) !void {
        // SAFETY: header and payload written immediately below via struct assignment and memcpy
        var buffer: [2048]u8 = undefined;
        const header: *VirtioNetHeader = @ptrCast(@alignCast(&buffer[0]));
        header.* = VirtioNetHeader{
            .flags = 0,
            .gso_type = 0,
            .hdr_len = @sizeOf(VirtioNetHeader),
            .gso_size = 0,
            .csum_start = 0,
            .csum_offset = 0,
            .num_buffers = 1,
        };

        const header_size = VIRTIO_NET_HEADER_SIZE;
        @memcpy(buffer[header_size .. header_size + packet.len], packet);

        _ = try self.addBuffer(&self.tx_queue, buffer[0 .. header_size + packet.len], false);
        self.notify(&self.tx_queue, 1);

        self.processUsedBuffers(&self.tx_queue);
    }

    pub fn receive(self: *VirtioNetDevice) ?[]u8 {
        const packet = self.claimReceive() orelse return null;
        const copy_len = @min(packet.data.len, self.rx_poll_buffer.len);
        @memcpy(self.rx_poll_buffer[0..copy_len], packet.data[0..copy_len]);
        self.releaseReceived(packet.handle);
        return self.rx_poll_buffer[0..copy_len];
    }

    pub fn claimReceive(self: *VirtioNetDevice) ?network.OwnedRxPacket {
        self.rx_lock.acquire();
        defer self.rx_lock.release();

        while (self.rx_queue.last_used_idx != self.rx_queue.used.idx) {
            const used_elem = &self.rx_queue.used.ring[self.rx_queue.last_used_idx % self.rx_queue.num];
            const desc_idx: u16 = @truncate(used_elem.id);
            const len = used_elem.len;
            self.rx_queue.last_used_idx +%= 1;

            if (len <= VIRTIO_NET_HEADER_SIZE) {
                self.recycleRxDescriptor(desc_idx);
                self.notify(&self.rx_queue, 0);
                continue;
            }

            const buffer_addr = self.rx_queue.desc[desc_idx].addr;
            const packet_start = buffer_addr + VIRTIO_NET_HEADER_SIZE;
            const packet_len = @min(len - VIRTIO_NET_HEADER_SIZE, VIRTIO_BUFFER_SIZE - VIRTIO_NET_HEADER_SIZE);

            return .{
                .data = @as([*]u8, @ptrFromInt(@as(usize, @intCast(packet_start))))[0..packet_len],
                .mac = self.mac_addr,
                .handle = desc_idx,
                .release = releaseClaimedPacket,
            };
        }

        return null;
    }

    pub fn releaseReceived(self: *VirtioNetDevice, handle: usize) void {
        if (handle >= self.rx_queue.num) return;

        self.rx_lock.acquire();
        self.recycleRxDescriptor(@intCast(handle));
        self.notify(&self.rx_queue, 0);
        self.rx_lock.release();
    }

    fn recycleRxDescriptor(self: *VirtioNetDevice, desc_idx: u16) void {
        const buffer_addr = @as(usize, @intCast(self.rx_queue.desc[desc_idx].addr));
        const buffer = @as([*]u8, @ptrFromInt(buffer_addr))[0..VIRTIO_BUFFER_SIZE];

        self.rx_queue.desc[desc_idx].addr = @intFromPtr(buffer.ptr);
        self.rx_queue.desc[desc_idx].len = @intCast(buffer.len);
        self.rx_queue.desc[desc_idx].flags = VIRTQ_DESC_F_WRITE;
        self.rx_queue.desc_state[desc_idx] = .{
            .data = @as(*anyopaque, @ptrCast(buffer.ptr)),
            .len = @intCast(buffer.len),
            .next = 0,
        };

        const avail_idx = self.rx_queue.avail.idx;
        self.rx_queue.avail.ring[avail_idx % self.rx_queue.num] = desc_idx;
        asm volatile ("" ::: .{ .memory = true });
        self.rx_queue.avail.idx = avail_idx +% 1;
        asm volatile ("" ::: .{ .memory = true });
    }
};

var virtio_net: ?VirtioNetDevice = null;

fn processInterrupt(dev: *VirtioNetDevice) void {
    const isr_status = dev.isr_cfg.*;

    if (isr_status & 1 != 0) {
        while (dev.claimReceive()) |packet| {
            _ = network.enqueueBorrowedRx(packet);
        }
    }
}

fn virtio_interrupt_handler(frame: *isr.InterruptFrame) void {
    _ = frame;
    if (virtio_net) |*dev| {
        processInterrupt(dev);
    }
}

pub fn runInterruptSelfTestChecked() bool {
    var common_cfg: VirtioCommonCfg = std.mem.zeroes(VirtioCommonCfg);
    var device_cfg: VirtioNetConfig = std.mem.zeroes(VirtioNetConfig);
    var isr_status: u8 = 1;
    var notify_slot: u16 = 0xFFFF;
    var rx_desc = [_]VirtqDesc{std.mem.zeroes(VirtqDesc)} ** 256;
    var tx_desc = [_]VirtqDesc{std.mem.zeroes(VirtqDesc)} ** 256;
    var rx_avail: VirtqAvail = std.mem.zeroes(VirtqAvail);
    var tx_avail: VirtqAvail = std.mem.zeroes(VirtqAvail);
    var rx_used: VirtqUsed = std.mem.zeroes(VirtqUsed);
    var tx_used: VirtqUsed = std.mem.zeroes(VirtqUsed);
    const rx_buffer_mem = memory.kmalloc(VIRTIO_BUFFER_SIZE) orelse return false;
    defer memory.kfree(rx_buffer_mem);

    const rx_buffer: [*]u8 = @ptrCast(rx_buffer_mem);
    const sender_ip: u32 = 0xC0A801F2;
    const target_ip: u32 = 0xC0A80102;
    const sender_mac = [6]u8{ 0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x03 };
    const target_mac = [6]u8{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x03 };
    const header_size = VIRTIO_NET_HEADER_SIZE;
    var frame: [ethernet.ETH_HEADER_SIZE + @sizeOf(arp.ARPHeader)]u8 = undefined;
    writeSyntheticArpReply(&frame, sender_ip, target_ip, sender_mac, target_mac);
    @memset(rx_buffer[0..VIRTIO_BUFFER_SIZE], 0);
    @memcpy(rx_buffer[header_size .. header_size + frame.len], frame[0..]);

    rx_desc[0].addr = @intFromPtr(rx_buffer);
    rx_desc[0].len = @intCast(VIRTIO_BUFFER_SIZE);
    rx_desc[0].flags = VIRTQ_DESC_F_WRITE;

    var fake = VirtioNetDevice{
        .pci_device = .{ .bus = 0, .device = 0, .function = 0, .vendor_id = 0, .device_id = 0, .class_code = 0, .subclass = 0, .prog_if = 0, .bar0 = 0, .bar1 = 0, .bar2 = 0, .bar3 = 0, .bar4 = 0, .bar5 = 0 },
        .common_cfg = &common_cfg,
        .device_cfg = &device_cfg,
        .notify_base = @intFromPtr(&notify_slot),
        .notify_off_multiplier = 0,
        .isr_cfg = @ptrCast(&isr_status),
        .mac_addr = target_mac,
        .rx_queue = .{
            .num = VIRTQUEUE_SIZE,
            .desc = &rx_desc,
            .avail = &rx_avail,
            .used = &rx_used,
            .notify_off = 0,
            .last_used_idx = 0,
            .free_head = 1,
            .num_free = VIRTQUEUE_SIZE - 1,
            .desc_state = [_]Virtqueue.DescState{.{ .data = null, .len = 0, .next = 0 }} ** 256,
        },
        .tx_queue = .{
            .num = VIRTQUEUE_SIZE,
            .desc = &tx_desc,
            .avail = &tx_avail,
            .used = &tx_used,
            .notify_off = 0,
            .last_used_idx = 0,
            .free_head = 0,
            .num_free = VIRTQUEUE_SIZE,
            .desc_state = [_]Virtqueue.DescState{.{ .data = null, .len = 0, .next = 0 }} ** 256,
        },
        .rx_buffers = rx_buffer,
        .tx_buffers = rx_buffer,
        .rx_lock = sync.SpinLock.init(),
        .rx_poll_buffer = undefined,
    };
    fake.rx_queue.used.idx = 1;
    fake.rx_queue.used.ring[0] = .{ .id = 0, .len = @intCast(header_size + frame.len) };

    const previous = virtio_net;
    virtio_net = fake;
    defer virtio_net = previous;

    if (virtio_net) |*dev| {
        processInterrupt(dev);
        const resolved = arp.resolve(sender_ip) orelse return false;
        return macEquals(resolved, sender_mac) and dev.rx_queue.avail.idx == 1 and notify_slot == 0;
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
    vga.print("Initializing VirtIO network driver...\n");

    var bus: u16 = 0;
    while (bus < 256) : (bus += 1) {
        var device: u8 = 0;
        while (device < 32) : (device += 1) {
            var func: u8 = 0;
            while (func < 8) : (func += 1) {
                if (pci.checkDevice(@intCast(bus), device, func)) |pci_device| {
                    if (pci_device.vendor_id == VIRTIO_VENDOR_ID and
                        (pci_device.device_id == VIRTIO_NET_DEVICE_ID or
                            pci_device.device_id == VIRTIO_NET_MODERN_ID or
                            (pci_device.device_id >= 0x1040 and pci_device.device_id <= 0x107F)))
                    {
                        vga.print("Found VirtIO network device!\n");
                        initDevice(pci_device);
                        return;
                    }
                }
            }
        }
    }

    vga.print("No VirtIO network device found.\n");
}

fn initDevice(pci_device: pci.PCIDevice) void {
    var dev = VirtioNetDevice{
        .pci_device = pci_device,
        // SAFETY: populated by findCapabilities call below
        .common_cfg = undefined,
        // SAFETY: populated by findCapabilities call below
        .device_cfg = undefined,
        // SAFETY: populated by findCapabilities call below
        .notify_base = undefined,
        // SAFETY: populated by findCapabilities call below
        .notify_off_multiplier = undefined,
        // SAFETY: populated by findCapabilities call below
        .isr_cfg = undefined,
        // SAFETY: populated by reading device MAC registers after feature negotiation
        .mac_addr = undefined,
        // SAFETY: initialized by setupVirtqueue call below
        .rx_queue = undefined,
        // SAFETY: initialized by setupVirtqueue call below
        .tx_queue = undefined,
        // SAFETY: allocated and filled when populating rx descriptors
        .rx_buffers = undefined,
        // SAFETY: allocated when setting up tx descriptors
        .tx_buffers = undefined,
        .rx_lock = sync.SpinLock.init(),
        .rx_poll_buffer = undefined,
    };

    if (!findCapabilities(&dev)) {
        vga.print("Failed to find VirtIO capabilities\n");
        return;
    }

    dev.commonFieldPtr(u8, "device_status").* = VIRTIO_STATUS_RESET;
    dev.commonFieldPtr(u8, "device_status").* = VIRTIO_STATUS_ACKNOWLEDGE;
    dev.commonFieldPtr(u8, "device_status").* |= VIRTIO_STATUS_DRIVER;

    var features = dev.readFeatures();
    features &= (VIRTIO_NET_F_MAC | VIRTIO_NET_F_STATUS);
    dev.writeFeatures(features);

    dev.commonFieldPtr(u8, "device_status").* |= VIRTIO_STATUS_FEATURES_OK;

    if ((dev.commonFieldPtr(u8, "device_status").* & VIRTIO_STATUS_FEATURES_OK) == 0) {
        vga.print("VirtIO feature negotiation failed\n");
        return;
    }

    dev.mac_addr = dev.deviceFieldPtr([6]u8, "mac").*;

    vga.print("VirtIO MAC: ");
    for (dev.mac_addr, 0..) |byte, i| {
        const high = byte >> 4;
        const low = byte & 0x0F;
        vga.printChar(if (high < 10) '0' + high else 'A' + high - 10);
        vga.printChar(if (low < 10) '0' + low else 'A' + low - 10);
        if (i < 5) vga.print(":");
    }
    vga.print("\n");

    dev.setupQueue(&dev.rx_queue, 0, VIRTQUEUE_SIZE) catch {
        vga.print("Failed to setup RX queue\n");
        return;
    };

    dev.setupQueue(&dev.tx_queue, 1, VIRTQUEUE_SIZE) catch {
        vga.print("Failed to setup TX queue\n");
        return;
    };

    const rx_buffer_size = VIRTIO_BUFFER_SIZE * VIRTQUEUE_SIZE;
    const rx_mem = memory.kmalloc(rx_buffer_size) orelse {
        vga.print("Failed to allocate RX buffers\n");
        return;
    };
    dev.rx_buffers = @as([*]u8, @ptrCast(rx_mem));

    for (0..VIRTQUEUE_SIZE) |i| {
        const buffer = dev.rx_buffers[i * VIRTIO_BUFFER_SIZE .. (i + 1) * VIRTIO_BUFFER_SIZE];
        _ = dev.addBuffer(&dev.rx_queue, buffer, true) catch break;
    }
    dev.notify(&dev.rx_queue, 0);

    const irq_line = pci.readConfigByte(pci_device.bus, pci_device.device, pci_device.function, 0x3C);
    isr.registerHandler(0x20 + irq_line, virtio_interrupt_handler);

    pci.writeConfigWord(pci_device.bus, pci_device.device, pci_device.function, 0x04, pci.readConfigWord(pci_device.bus, pci_device.device, pci_device.function, 0x04) | 0x06);

    dev.commonFieldPtr(u8, "device_status").* |= VIRTIO_STATUS_DRIVER_OK;

    virtio_net = dev;
    network.setNetworkDevice(&virtio_network_device);

    vga.print("VirtIO network initialized successfully!\n");
}

fn findCapabilities(dev: *VirtioNetDevice) bool {
    var cap_offset = pci.readConfigByte(dev.pci_device.bus, dev.pci_device.device, dev.pci_device.function, 0x34);

    while (cap_offset != 0) {
        const cap_id = pci.readConfigByte(dev.pci_device.bus, dev.pci_device.device, dev.pci_device.function, cap_offset);

        if (cap_id == 0x09) {
            const cap_len = pci.readConfigByte(dev.pci_device.bus, dev.pci_device.device, dev.pci_device.function, cap_offset + 2);

            if (cap_len >= 16) {
                const cfg_type = pci.readConfigByte(dev.pci_device.bus, dev.pci_device.device, dev.pci_device.function, cap_offset + 3);
                const bar = pci.readConfigByte(dev.pci_device.bus, dev.pci_device.device, dev.pci_device.function, cap_offset + 4);
                const offset = pci.readConfigDword(dev.pci_device.bus, dev.pci_device.device, dev.pci_device.function, cap_offset + 8);
                const length = pci.readConfigDword(dev.pci_device.bus, dev.pci_device.device, dev.pci_device.function, cap_offset + 12);

                const bar_addr = switch (bar) {
                    0 => dev.pci_device.bar0,
                    1 => dev.pci_device.bar1,
                    2 => dev.pci_device.bar2,
                    3 => dev.pci_device.bar3,
                    4 => dev.pci_device.bar4,
                    5 => dev.pci_device.bar5,
                    else => 0,
                };

                if (bar_addr != 0) {
                    const base_addr = (bar_addr & 0xFFFFFFF0) + offset;
                    const aligned_base = base_addr & ~@as(u32, 0xFFF);
                    const end_addr = (base_addr + length + 0xFFF) & ~@as(u32, 0xFFF);
                    if (end_addr > aligned_base) {
                        paging.map_range(aligned_base, aligned_base, end_addr - aligned_base, paging.PAGE_PRESENT | paging.PAGE_WRITABLE | paging.PAGE_CACHE_DISABLE);
                    }

                    switch (cfg_type) {
                        VIRTIO_PCI_CAP_COMMON_CFG => {
                            dev.common_cfg = @as(*align(1) volatile VirtioCommonCfg, @ptrFromInt(base_addr));
                        },
                        VIRTIO_PCI_CAP_NOTIFY_CFG => {
                            dev.notify_base = base_addr;
                            if (cap_len >= 20) {
                                dev.notify_off_multiplier = pci.readConfigDword(dev.pci_device.bus, dev.pci_device.device, dev.pci_device.function, cap_offset + 16);
                            }
                        },
                        VIRTIO_PCI_CAP_ISR_CFG => {
                            dev.isr_cfg = @as(*align(1) volatile u8, @ptrFromInt(base_addr));
                        },
                        VIRTIO_PCI_CAP_DEVICE_CFG => {
                            dev.device_cfg = @as(*align(1) VirtioNetConfig, @ptrFromInt(base_addr));
                        },
                        else => {},
                    }
                }
            }
        }

        cap_offset = pci.readConfigByte(dev.pci_device.bus, dev.pci_device.device, dev.pci_device.function, cap_offset + 1);
    }

    return @intFromPtr(dev.common_cfg) != 0 and
        @intFromPtr(dev.device_cfg) != 0 and
        @intFromPtr(dev.isr_cfg) != 0 and
        dev.notify_base != 0;
}

const virtio_network_device = network.NetworkDevice{
    .send = virtioSend,
    .receive = virtioReceive,
    .getMacAddress = virtioGetMacAddress,
};

fn virtioSend(data: []const u8) void {
    if (virtio_net) |*dev| {
        dev.send(data) catch {};
    }
}

fn virtioReceive() ?[]u8 {
    if (virtio_net) |*dev| {
        return dev.receive();
    }
    return null;
}

fn releaseClaimedPacket(handle: usize) void {
    if (virtio_net) |*dev| {
        dev.releaseReceived(handle);
    }
}

fn virtioGetMacAddress() [6]u8 {
    if (virtio_net) |*dev| {
        return dev.mac_addr;
    }
    return [_]u8{0} ** 6;
}

pub fn isInitialized() bool {
    return virtio_net != null;
}
