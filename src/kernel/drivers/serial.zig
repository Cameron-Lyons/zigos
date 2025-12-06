const COM1_BASE: u16 = 0x3F8;

const SERIAL_DATA = COM1_BASE + 0;
const SERIAL_INTERRUPT_ENABLE = COM1_BASE + 1;
const SERIAL_FIFO_CONTROL = COM1_BASE + 2;
const SERIAL_LINE_CONTROL = COM1_BASE + 3;
const SERIAL_MODEM_CONTROL = COM1_BASE + 4;
const SERIAL_LINE_STATUS = COM1_BASE + 5;
const SERIAL_MODEM_STATUS = COM1_BASE + 6;
const SERIAL_SCRATCH = COM1_BASE + 7;

const LINE_STATUS_DATA_READY = 0x01;
const LINE_STATUS_OVERRUN = 0x02;
const LINE_STATUS_PARITY_ERROR = 0x04;
const LINE_STATUS_FRAMING_ERROR = 0x08;
const LINE_STATUS_BREAK = 0x10;
const LINE_STATUS_TRANSMIT_HOLD_EMPTY = 0x20;
const LINE_STATUS_TRANSMIT_EMPTY = 0x40;
const LINE_STATUS_ERROR = 0x80;

var serial_initialized: bool = false;

fn outb(port: u16, value: u8) void {
    asm volatile ("outb %[value], %[port]"
        :
        : [value] "{al}" (value),
          [port] "N{dx}" (port),
    );
}

fn inb(port: u16) u8 {
    return asm volatile ("inb %[port], %[result]"
        : [result] "={al}" (-> u8),
        : [port] "N{dx}" (port),
    );
}

pub fn init() void {
    outb(SERIAL_INTERRUPT_ENABLE, 0x00);

    outb(SERIAL_LINE_CONTROL, 0x80);

    outb(SERIAL_DATA, 0x03);
    outb(SERIAL_INTERRUPT_ENABLE, 0x00);

    outb(SERIAL_LINE_CONTROL, 0x03);

    outb(SERIAL_FIFO_CONTROL, 0xC7);

    outb(SERIAL_MODEM_CONTROL, 0x0B);

    outb(SERIAL_MODEM_CONTROL, 0x1E);
    outb(SERIAL_DATA, 0xAE);

    if (inb(SERIAL_DATA) != 0xAE) {
        serial_initialized = false;
        return;
    }

    outb(SERIAL_MODEM_CONTROL, 0x0F);
    serial_initialized = true;
}

fn isTransmitEmpty() bool {
    return (inb(SERIAL_LINE_STATUS) & LINE_STATUS_TRANSMIT_HOLD_EMPTY) != 0;
}

pub fn putChar(c: u8) void {
    if (!serial_initialized) {
        return;
    }

    var timeout: u32 = 10000;
    while (!isTransmitEmpty() and timeout > 0) {
        timeout -= 1;
    }

    outb(SERIAL_DATA, c);
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

