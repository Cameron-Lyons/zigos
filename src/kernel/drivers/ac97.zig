const std = @import("std");
const pci = @import("pci.zig");
const memory = @import("../memory/memory.zig");
const vga = @import("vga.zig");
const io = @import("../utils/io.zig");
const isr = @import("../interrupts/isr.zig");

const AC97_VENDOR_INTEL = 0x8086;
const AC97_DEVICE_ICH = 0x2415;
const AC97_DEVICE_ICH0 = 0x2425;
const AC97_DEVICE_ICH2 = 0x2445;
const AC97_DEVICE_ICH3 = 0x2485;
const AC97_DEVICE_ICH4 = 0x24C5;
const AC97_DEVICE_ICH5 = 0x24D5;
const AC97_DEVICE_ICH6 = 0x266E;
const AC97_DEVICE_ICH7 = 0x27DE;

const NAM_RESET = 0x00;
const NAM_MASTER_VOLUME = 0x02;
const NAM_PC_BEEP = 0x0A;
const NAM_PCM_OUT_VOLUME = 0x18;
const NAM_EXT_AUDIO_ID = 0x28;
const NAM_EXT_AUDIO_CTRL = 0x2A;
const NAM_PCM_FRONT_DAC_RATE = 0x2C;
const NAM_PCM_LR_ADC_RATE = 0x32;

const NABM_GLOB_CNT = 0x2C;
const NABM_GLOB_STA = 0x30;

const PO_BDBAR = 0x10;
const PO_LVI = 0x15;
const PO_SR = 0x16;
const PO_CR = 0x1B;

const CR_RPBM = 1 << 0;
const CR_RR = 1 << 1;
const CR_LVBIE = 1 << 2;
const CR_IOCE = 1 << 4;

const SR_LVBCI = 1 << 2;
const SR_BCIS = 1 << 3;
const SR_FIFOE = 1 << 4;

const GLOB_CNT_COLD_RESET = 1 << 1;
const GLOB_STA_PCR = 1 << 8;

const BDL_ENTRIES = 32;
const BUFFER_SIZE = 0x10000;
const SAMPLE_RATE = 48000;

const BufferDescriptor = extern struct {
    addr: u32,
    samples: u16,
    flags: u16,
};

const AC97Device = struct {
    pci_device: pci.PCIDevice,
    nam_base: u16,
    nabm_base: u16,
    irq: u8,
    bdl: [*]BufferDescriptor,
    audio_buffer: [*]u8,
    current_buffer: u8,
    is_playing: bool,
    volume: u16,
    sample_rate: u32,

    fn reset(self: *AC97Device) void {
        io.outl(self.nabm_base + NABM_GLOB_CNT, GLOB_CNT_COLD_RESET);
        busyWait(100000);

        io.outl(self.nabm_base + NABM_GLOB_CNT, 0);
        busyWait(100000);

        var timeout: u32 = 1000;
        while (timeout > 0) : (timeout -= 1) {
            const status = io.inl(self.nabm_base + NABM_GLOB_STA);
            if ((status & GLOB_STA_PCR) != 0) {
                break;
            }
            busyWait(1000);
        }

        if (timeout == 0) {
            vga.print("AC97 codec not ready\n");
            return;
        }

        io.outw(self.nam_base + NAM_RESET, 0);
        busyWait(100000);

        io.outw(self.nam_base + NAM_MASTER_VOLUME, 0x0000);
        io.outw(self.nam_base + NAM_PCM_OUT_VOLUME, 0x0808);
        io.outw(self.nam_base + NAM_PC_BEEP, 0x0000);

        if (self.sample_rate != 48000) {
            const ext_id = io.inw(self.nam_base + NAM_EXT_AUDIO_ID);
            if ((ext_id & 1) != 0) {
                io.outw(self.nam_base + NAM_EXT_AUDIO_CTRL, io.inw(self.nam_base + NAM_EXT_AUDIO_CTRL) | 1);
                io.outw(self.nam_base + NAM_PCM_FRONT_DAC_RATE, @as(u16, @intCast(self.sample_rate)));
                io.outw(self.nam_base + NAM_PCM_LR_ADC_RATE, @as(u16, @intCast(self.sample_rate)));
            }
        }
    }

    fn setupBuffers(self: *AC97Device) void {
        const bdl_mem = memory.kmalloc(@sizeOf(BufferDescriptor) * BDL_ENTRIES + 8) orelse return;
        self.bdl = @as([*]BufferDescriptor, @ptrCast(@alignCast(bdl_mem)));

        const audio_mem = memory.kmalloc(BUFFER_SIZE * 2) orelse {
            memory.kfree(bdl_mem);
            return;
        };
        self.audio_buffer = @as([*]u8, @ptrCast(audio_mem));

        for (0..BDL_ENTRIES) |i| {
            const buffer_offset = (i % 2) * BUFFER_SIZE;
            self.bdl[i].addr = @intFromPtr(&self.audio_buffer[buffer_offset]);
            self.bdl[i].samples = BUFFER_SIZE / 2;
            self.bdl[i].flags = if (i == BDL_ENTRIES - 1) 0x8000 else 0x0000;
        }

        io.outl(self.nabm_base + PO_BDBAR, @intFromPtr(self.bdl));

        io.outb(self.nabm_base + PO_LVI, BDL_ENTRIES - 1);
    }

    pub fn play(self: *AC97Device, samples: []const i16) void {
        if (samples.len == 0) return;

        const buffer_samples = BUFFER_SIZE / 2;
        const current_offset = @as(usize, self.current_buffer) * BUFFER_SIZE;
        const dest: [*]i16 = @ptrCast(@alignCast(&self.audio_buffer[current_offset]));

        const copy_count = @min(samples.len, buffer_samples);
        @memcpy(dest[0..copy_count], samples[0..copy_count]);

        if (copy_count < buffer_samples) {
            @memset(dest[copy_count..buffer_samples], 0);
        }

        if (!self.is_playing) {
            io.outb(self.nabm_base + PO_CR, CR_RPBM | CR_LVBIE | CR_IOCE);
            self.is_playing = true;
        }

        self.current_buffer = (self.current_buffer + 1) % 2;
    }

    pub fn stop(self: *AC97Device) void {
        io.outb(self.nabm_base + PO_CR, 0);
        io.outb(self.nabm_base + PO_CR, CR_RR);
        self.is_playing = false;
    }

    pub fn setVolume(self: *AC97Device, left: u8, right: u8) void {
        const vol = (@as(u16, 63 - (left & 0x3F)) << 8) | (63 - (right & 0x3F));
        io.outw(self.nam_base + NAM_MASTER_VOLUME, vol);
        io.outw(self.nam_base + NAM_PCM_OUT_VOLUME, vol);
        self.volume = vol;
    }

    pub fn getVolume(self: *AC97Device) struct { left: u8, right: u8 } {
        const vol = io.inw(self.nam_base + NAM_MASTER_VOLUME);
        return .{
            .left = 63 - @as(u8, @intCast((vol >> 8) & 0x3F)),
            .right = 63 - @as(u8, @intCast(vol & 0x3F)),
        };
    }
};

var ac97_device: ?AC97Device = null;

fn ac97_interrupt_handler(frame: *isr.InterruptFrame) void {
    _ = frame;
    if (ac97_device) |*dev| {
        const status = io.inw(dev.nabm_base + PO_SR);

        if ((status & SR_LVBCI) != 0) {
            io.outw(dev.nabm_base + PO_SR, SR_LVBCI);
        }

        if ((status & SR_BCIS) != 0) {
            io.outw(dev.nabm_base + PO_SR, SR_BCIS);
        }

        if ((status & SR_FIFOE) != 0) {
            io.outw(dev.nabm_base + PO_SR, SR_FIFOE);
        }
    }
}

pub fn init() void {
    vga.print("Initializing AC97 audio...\n");

    var bus: u16 = 0;
    while (bus < 256) : (bus += 1) {
        var device: u8 = 0;
        while (device < 32) : (device += 1) {
            var func: u8 = 0;
            while (func < 8) : (func += 1) {
                if (pci.checkDevice(@intCast(bus), device, func)) |pci_device| {
                    if (pci_device.vendor_id == AC97_VENDOR_INTEL) {
                        switch (pci_device.device_id) {
                            AC97_DEVICE_ICH,
                            AC97_DEVICE_ICH0,
                            AC97_DEVICE_ICH2,
                            AC97_DEVICE_ICH3,
                            AC97_DEVICE_ICH4,
                            AC97_DEVICE_ICH5,
                            AC97_DEVICE_ICH6,
                            AC97_DEVICE_ICH7,
                            => {
                                vga.print("Found Intel AC97 audio controller\n");
                                initDevice(pci_device);
                                return;
                            },
                            else => {},
                        }
                    }
                }
            }
        }
    }

    vga.print("No AC97 audio controller found\n");
}

fn initDevice(pci_device: pci.PCIDevice) void {
    var dev = AC97Device{
        .pci_device = pci_device,
        .nam_base = @as(u16, @intCast(pci_device.bar0 & 0xFFFE)),
        .nabm_base = @as(u16, @intCast(pci_device.bar1 & 0xFFFE)),
        .irq = pci.readConfigByte(pci_device.bus, pci_device.device, pci_device.function, 0x3C),
        // SAFETY: initialized by setupBuffers call below
        .bdl = undefined,
        // SAFETY: initialized by setupBuffers call below
        .audio_buffer = undefined,
        .current_buffer = 0,
        .is_playing = false,
        .volume = 0x0000,
        .sample_rate = SAMPLE_RATE,
    };

    pci.writeConfigWord(pci_device.bus, pci_device.device, pci_device.function, 0x04,
        pci.readConfigWord(pci_device.bus, pci_device.device, pci_device.function, 0x04) | 0x05);

    dev.reset();
    dev.setupBuffers();

    isr.registerHandler(0x20 + dev.irq, ac97_interrupt_handler);

    dev.setVolume(32, 32);

    ac97_device = dev;

    vga.print("AC97 audio initialized\n");
    playBeep();
}

pub fn playBeep() void {
    if (ac97_device) |*dev| {
        // SAFETY: filled by the following sine wave generation loop
        var beep_samples: [4800]i16 = undefined;
        const frequency = 440.0;
        const amplitude = 0x2000;

        for (&beep_samples, 0..) |*sample, i| {
            const t = @as(f32, @floatFromInt(i)) / @as(f32, SAMPLE_RATE);
            const value = @sin(2.0 * std.math.pi * frequency * t) * @as(f32, amplitude);
            sample.* = @as(i16, @intFromFloat(value));
        }

        dev.play(&beep_samples);
    }
}

pub fn playSamples(samples: []const i16) void {
    if (ac97_device) |*dev| {
        dev.play(samples);
    }
}

pub fn stopPlayback() void {
    if (ac97_device) |*dev| {
        dev.stop();
    }
}

pub fn setMasterVolume(left: u8, right: u8) void {
    if (ac97_device) |*dev| {
        dev.setVolume(left, right);
    }
}

fn busyWait(microseconds: u32) void {
    var i: u32 = 0;
    while (i < microseconds * 10) : (i += 1) {
        asm volatile ("pause");
    }
}

pub fn isInitialized() bool {
    return ac97_device != null;
}