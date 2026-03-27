const COM1_BASE: u16 = 0x3F8;
const io = @import("../utils/io.zig");

const SERIAL_DATA = COM1_BASE + 0;
const SERIAL_INTERRUPT_ENABLE = COM1_BASE + 1;
const SERIAL_FIFO_CONTROL = COM1_BASE + 2;
const SERIAL_LINE_CONTROL = COM1_BASE + 3;
const SERIAL_MODEM_CONTROL = COM1_BASE + 4;
const SERIAL_LINE_STATUS = COM1_BASE + 5;
const LINE_STATUS_DATA_READY = 0x01;
const LINE_STATUS_TRANSMIT_HOLD_EMPTY = 0x20;

var serial_initialized: bool = false;

pub fn init() void {
    io.outb(SERIAL_INTERRUPT_ENABLE, 0x00);

    io.outb(SERIAL_LINE_CONTROL, 0x80);

    io.outb(SERIAL_DATA, 0x03);
    io.outb(SERIAL_INTERRUPT_ENABLE, 0x00);

    io.outb(SERIAL_LINE_CONTROL, 0x03);

    io.outb(SERIAL_FIFO_CONTROL, 0xC7);

    io.outb(SERIAL_MODEM_CONTROL, 0x0B);

    io.outb(SERIAL_MODEM_CONTROL, 0x1E);
    io.outb(SERIAL_DATA, 0xAE);

    if (io.inb(SERIAL_DATA) != 0xAE) {
        serial_initialized = false;
        return;
    }

    io.outb(SERIAL_MODEM_CONTROL, 0x0F);
    serial_initialized = true;
}

fn isTransmitEmpty() bool {
    return (io.inb(SERIAL_LINE_STATUS) & LINE_STATUS_TRANSMIT_HOLD_EMPTY) != 0;
}

fn isDataReady() bool {
    return (io.inb(SERIAL_LINE_STATUS) & LINE_STATUS_DATA_READY) != 0;
}

pub fn putChar(c: u8) void {
    if (!serial_initialized) {
        return;
    }

    var timeout: u32 = 10000;
    while (!isTransmitEmpty() and timeout > 0) {
        timeout -= 1;
    }

    io.outb(SERIAL_DATA, c);

    timeout = 10000;
    while (!isTransmitEmpty() and timeout > 0) {
        timeout -= 1;
    }
}

pub fn flush() void {
    if (!serial_initialized) {
        return;
    }

    var timeout: u32 = 10000;
    while (!isTransmitEmpty() and timeout > 0) {
        timeout -= 1;
    }
}

pub fn hasChar() bool {
    return serial_initialized and isDataReady();
}

pub fn getchar() ?u8 {
    if (!hasChar()) {
        return null;
    }
    return io.inb(SERIAL_DATA);
}

pub fn print(str: []const u8) void {
    if (!serial_initialized) {
        return;
    }

    for (str) |c| {
        putChar(c);
    }
}

pub fn isInitialized() bool {
    return serial_initialized;
}
