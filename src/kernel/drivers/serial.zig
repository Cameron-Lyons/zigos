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
const LINE_CONTROL_DLAB = 0x80;
const LINE_CONTROL_8N1 = 0x03;
const INTERRUPTS_DISABLED = 0x00;
const BAUD_DIVISOR_38400_LOW = 0x03;
const FIFO_ENABLE_CLEAR_14_BYTE = 0xC7;
const MODEM_CONTROL_LOOPBACK = 0x1E;
const MODEM_CONTROL_READY = 0x0F;
const MODEM_CONTROL_IRQS_ENABLED = 0x0B;
const LOOPBACK_TEST_BYTE = 0xAE;
const SERIAL_WAIT_LIMIT: u32 = 10000;

var serial_initialized: bool = false;

pub fn init() void {
    io.outb(SERIAL_INTERRUPT_ENABLE, INTERRUPTS_DISABLED);

    io.outb(SERIAL_LINE_CONTROL, LINE_CONTROL_DLAB);

    io.outb(SERIAL_DATA, BAUD_DIVISOR_38400_LOW);
    io.outb(SERIAL_INTERRUPT_ENABLE, INTERRUPTS_DISABLED);

    io.outb(SERIAL_LINE_CONTROL, LINE_CONTROL_8N1);

    io.outb(SERIAL_FIFO_CONTROL, FIFO_ENABLE_CLEAR_14_BYTE);

    io.outb(SERIAL_MODEM_CONTROL, MODEM_CONTROL_IRQS_ENABLED);

    io.outb(SERIAL_MODEM_CONTROL, MODEM_CONTROL_LOOPBACK);
    io.outb(SERIAL_DATA, LOOPBACK_TEST_BYTE);

    if (io.inb(SERIAL_DATA) != LOOPBACK_TEST_BYTE) {
        serial_initialized = false;
        return;
    }

    io.outb(SERIAL_MODEM_CONTROL, MODEM_CONTROL_READY);
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

    var timeout: u32 = SERIAL_WAIT_LIMIT;
    while (!isTransmitEmpty() and timeout > 0) {
        timeout -= 1;
    }

    io.outb(SERIAL_DATA, c);

    timeout = SERIAL_WAIT_LIMIT;
    while (!isTransmitEmpty() and timeout > 0) {
        timeout -= 1;
    }
}

pub fn flush() void {
    if (!serial_initialized) {
        return;
    }

    var timeout: u32 = SERIAL_WAIT_LIMIT;
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
