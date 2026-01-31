// zlint-disable suppressed-errors
const pci = @import("pci.zig");
const memory = @import("../memory/memory.zig");
const vga = @import("vga.zig");
const isr = @import("../interrupts/isr.zig");
const network = @import("../net/network.zig");

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
    common_cfg: *volatile VirtioCommonCfg,
    device_cfg: *VirtioNetConfig,
    notify_base: usize,
    notify_off_multiplier: u32,
    isr_cfg: *volatile u8,
    mac_addr: [6]u8,
    rx_queue: Virtqueue,
    tx_queue: Virtqueue,
    rx_buffers: [*]u8,
    tx_buffers: [*]u8,

    fn readFeatures(self: *VirtioNetDevice) u64 {
        self.common_cfg.device_feature_select = 0;
        const low = self.common_cfg.device_feature;
        self.common_cfg.device_feature_select = 1;
        const high = self.common_cfg.device_feature;
        return (@as(u64, high) << 32) | low;
    }

    fn writeFeatures(self: *VirtioNetDevice, features: u64) void {
        self.common_cfg.driver_feature_select = 0;
        self.common_cfg.driver_feature = @as(u32, @truncate(features));
        self.common_cfg.driver_feature_select = 1;
        self.common_cfg.driver_feature = @as(u32, @truncate(features >> 32));
    }

    fn setupQueue(self: *VirtioNetDevice, queue: *Virtqueue, index: u16, size: u16) !void {
        queue.num = size;

        const desc_size = @sizeOf(VirtqDesc) * size;
        const avail_size = @sizeOf(VirtqAvail) + @sizeOf(u16) * size;
        const used_size = @sizeOf(VirtqUsed) + @sizeOf(VirtqUsedElem) * size;
        const total_size = desc_size + avail_size + used_size;

        const queue_mem = memory.kmalloc(total_size + 4096) orelse return error.OutOfMemory;
        const queue_addr = (@intFromPtr(queue_mem) + 4095) & ~@as(usize, 4095);

        queue.desc = @as([*]VirtqDesc, @ptrFromInt(queue_addr));
        queue.avail = @as(*VirtqAvail, @ptrFromInt(queue_addr + desc_size));
        queue.used = @as(*VirtqUsed, @ptrFromInt(queue_addr + desc_size + avail_size));

        @memset(@as([*]u8, @ptrFromInt(queue_addr))[0..total_size], 0);

        for (0..size) |i| {
            queue.desc[i].next = @as(u16, @intCast((i + 1) % size));
            queue.desc_state[i] = .{ .data = null, .len = 0, .next = 0 };
        }
        queue.free_head = 0;
        queue.num_free = size;
        queue.last_used_idx = 0;

        self.common_cfg.queue_select = index;
        self.common_cfg.queue_size = size;
        self.common_cfg.queue_desc = queue_addr;
        self.common_cfg.queue_driver = queue_addr + desc_size;
        self.common_cfg.queue_device = queue_addr + desc_size + avail_size;
        self.common_cfg.queue_enable = 1;
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

        asm volatile ("" ::: "memory");

        queue.avail.idx = avail_idx +% 1;

        asm volatile ("" ::: "memory");

        return desc_idx;
    }

    fn notify(self: *VirtioNetDevice, queue_index: u16) void {
        const notify_addr = self.notify_base +
            @as(usize, self.common_cfg.queue_notify_off) * self.notify_off_multiplier;
        const notify_ptr: *volatile u16 = @ptrFromInt(notify_addr);
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

        const header_size = @sizeOf(VirtioNetHeader);
        @memcpy(buffer[header_size .. header_size + packet.len], packet);

        _ = try self.addBuffer(&self.tx_queue, buffer[0 .. header_size + packet.len], false);
        self.notify(1);

        self.processUsedBuffers(&self.tx_queue);
    }

    pub fn receive(self: *VirtioNetDevice) ?[]u8 {
        self.processUsedBuffers(&self.rx_queue);

        if (self.rx_queue.last_used_idx != self.rx_queue.used.idx) {
            const used_elem = &self.rx_queue.used.ring[self.rx_queue.last_used_idx % self.rx_queue.num];
            const len = used_elem.len;

            if (len > @sizeOf(VirtioNetHeader)) {
                const desc_idx: u16 = @truncate(used_elem.id);
                const buffer_addr = self.rx_queue.desc[desc_idx].addr;
                const packet_start = buffer_addr + @sizeOf(VirtioNetHeader);
                const packet_len = len - @sizeOf(VirtioNetHeader);

                self.rx_queue.last_used_idx +%= 1;

                // SAFETY: passed to addBuffer as a receive descriptor for the device to fill
                const buffer: [2048]u8 = undefined;
                _ = self.addBuffer(&self.rx_queue, &buffer, true) catch {
                    return null;
                };
                self.notify(0);

                return @as([*]u8, @ptrFromInt(@as(usize, @intCast(packet_start))))[0..packet_len];
            }
        }

        return null;
    }
};

var virtio_net: ?VirtioNetDevice = null;

fn virtio_interrupt_handler(frame: *isr.InterruptFrame) void {
    _ = frame;
    if (virtio_net) |*dev| {
        const isr_status = dev.isr_cfg.*;

        if (isr_status & 1 != 0) {
            while (dev.receive()) |packet| {
                network.processPacket(packet, dev.mac_addr);
            }
        }
    }
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
    };

    if (!findCapabilities(&dev)) {
        vga.print("Failed to find VirtIO capabilities\n");
        return;
    }

    dev.common_cfg.device_status = VIRTIO_STATUS_RESET;
    dev.common_cfg.device_status = VIRTIO_STATUS_ACKNOWLEDGE;
    dev.common_cfg.device_status |= VIRTIO_STATUS_DRIVER;

    var features = dev.readFeatures();
    features &= (VIRTIO_NET_F_MAC | VIRTIO_NET_F_STATUS);
    dev.writeFeatures(features);

    dev.common_cfg.device_status |= VIRTIO_STATUS_FEATURES_OK;

    if ((dev.common_cfg.device_status & VIRTIO_STATUS_FEATURES_OK) == 0) {
        vga.print("VirtIO feature negotiation failed\n");
        return;
    }

    @memcpy(&dev.mac_addr, &dev.device_cfg.mac);

    vga.print("VirtIO MAC: ");
    for (dev.mac_addr, 0..) |byte, i| {
        const high = byte >> 4;
        const low = byte & 0x0F;
        vga.printChar(if (high < 10) '0' + high else 'A' + high - 10);
        vga.printChar(if (low < 10) '0' + low else 'A' + low - 10);
        if (i < 5) vga.print(":");
    }
    vga.print("\n");

    dev.setupQueue(&dev.rx_queue, 0, 256) catch {
        vga.print("Failed to setup RX queue\n");
        return;
    };

    dev.setupQueue(&dev.tx_queue, 1, 256) catch {
        vga.print("Failed to setup TX queue\n");
        return;
    };

    const rx_buffer_size = 2048 * 256;
    const rx_mem = memory.kmalloc(rx_buffer_size) orelse {
        vga.print("Failed to allocate RX buffers\n");
        return;
    };
    dev.rx_buffers = @as([*]u8, @ptrCast(rx_mem));

    for (0..256) |i| {
        const buffer = dev.rx_buffers[i * 2048 .. (i + 1) * 2048];
        _ = dev.addBuffer(&dev.rx_queue, buffer, true) catch break;
    }
    dev.notify(0);

    const irq_line = pci.readConfigByte(pci_device.bus, pci_device.device, pci_device.function, 0x3C);
    isr.registerHandler(0x20 + irq_line, virtio_interrupt_handler);

    pci.writeConfigWord(pci_device.bus, pci_device.device, pci_device.function, 0x04, pci.readConfigWord(pci_device.bus, pci_device.device, pci_device.function, 0x04) | 0x06);

    dev.common_cfg.device_status |= VIRTIO_STATUS_DRIVER_OK;

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

                _ = length;

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

                    switch (cfg_type) {
                        VIRTIO_PCI_CAP_COMMON_CFG => {
                            dev.common_cfg = @as(*volatile VirtioCommonCfg, @ptrFromInt(base_addr));
                        },
                        VIRTIO_PCI_CAP_NOTIFY_CFG => {
                            dev.notify_base = base_addr;
                            if (cap_len >= 20) {
                                dev.notify_off_multiplier = pci.readConfigDword(dev.pci_device.bus, dev.pci_device.device, dev.pci_device.function, cap_offset + 16);
                            }
                        },
                        VIRTIO_PCI_CAP_ISR_CFG => {
                            dev.isr_cfg = @as(*volatile u8, @ptrFromInt(base_addr));
                        },
                        VIRTIO_PCI_CAP_DEVICE_CFG => {
                            dev.device_cfg = @as(*VirtioNetConfig, @ptrFromInt(base_addr));
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

fn virtioGetMacAddress() [6]u8 {
    if (virtio_net) |*dev| {
        return dev.mac_addr;
    }
    return [_]u8{0} ** 6;
}

pub fn isInitialized() bool {
    return virtio_net != null;
}
