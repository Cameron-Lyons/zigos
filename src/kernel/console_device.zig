const vga = @import("vga.zig");
const device = @import("device.zig");
const error_handler = @import("error.zig");

var console_dev: ?*device.Device = null;

fn console_open(dev: *device.Device) error_handler.Error!void {
    _ = dev;
}

fn console_close(dev: *device.Device) void {
    _ = dev;
}

fn console_read(dev: *device.Device, buffer: []u8, offset: usize) error_handler.Error!usize {
    _ = dev;
    _ = buffer;
    _ = offset;
    return error_handler.Error.NotImplemented;
}

fn console_write(dev: *device.Device, buffer: []const u8, offset: usize) error_handler.Error!usize {
    _ = dev;
    _ = offset;

    for (buffer) |byte| {
        vga.put_char(byte);
    }

    return buffer.len;
}

fn console_ioctl(dev: *device.Device, request: u32, arg: usize) error_handler.Error!i32 {
    _ = dev;

    const IOCTL_CLEAR_SCREEN = 1;
    const IOCTL_SET_COLOR = 2;

    switch (request) {
        IOCTL_CLEAR_SCREEN => {
            vga.clear();
            return 0;
        },
        IOCTL_SET_COLOR => {
            vga.clearWithColor(@intCast(arg));
            return 0;
        },
        else => return error_handler.Error.InvalidParameter,
    }
}

const console_ops = device.DeviceOps{
    .open = console_open,
    .close = console_close,
    .read = console_read,
    .write = console_write,
    .ioctl = console_ioctl,
};

pub fn init() !void {
    console_dev = try device.registerDevice("console", device.DeviceType.CharDevice, console_ops, null);
}

