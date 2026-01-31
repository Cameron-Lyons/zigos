const error_handler = @import("../utils/error.zig");
const memory = @import("../memory/memory.zig");

pub const DeviceType = enum {
    CharDevice,
    BlockDevice,
    NetworkDevice,
};

pub const DeviceOps = struct {
    open: ?*const fn (device: *Device) error_handler.Error!void,
    close: ?*const fn (device: *Device) void,
    read: ?*const fn (device: *Device, buffer: []u8, offset: usize) error_handler.Error!usize,
    write: ?*const fn (device: *Device, buffer: []const u8, offset: usize) error_handler.Error!usize,
    ioctl: ?*const fn (device: *Device, request: u32, arg: usize) error_handler.Error!i32,
};

pub const Device = struct {
    name: [64]u8,
    device_type: DeviceType,
    major: u16,
    minor: u16,
    ops: DeviceOps,
    private_data: ?*anyopaque,
    ref_count: u32,
    next: ?*Device,
};

var device_list: ?*Device = null;
var next_major: u16 = 1;

pub fn init() void {
    device_list = null;
    next_major = 1;
}

pub fn registerDevice(name: []const u8, device_type: DeviceType, ops: DeviceOps, private_data: ?*anyopaque) error_handler.Error!*Device {
    if (name.len >= 64) {
        return error_handler.Error.InvalidParameter;
    }

    const device_mem = memory.kmalloc(@sizeOf(Device)) orelse return error_handler.Error.OutOfMemory;
    const device: *Device = @ptrCast(@alignCast(device_mem));

    device.* = Device{
        .name = [_]u8{0} ** 64,
        .device_type = device_type,
        .major = next_major,
        .minor = 0,
        .ops = ops,
        .private_data = private_data,
        .ref_count = 0,
        .next = device_list,
    };

    @memcpy(device.name[0..name.len], name);

    device_list = device;
    next_major += 1;

    return device;
}

pub fn unregisterDevice(device: *Device) void {
    if (device_list == device) {
        device_list = device.next;
    } else {
        var current = device_list;
        while (current) |dev| {
            if (dev.next == device) {
                dev.next = device.next;
                break;
            }
            current = dev.next;
        }
    }

    memory.kfree(device);
}

pub fn findDevice(name: []const u8) ?*Device {
    var current = device_list;
    while (current) |device| {
        var i: usize = 0;
        while (i < name.len and i < 64 and device.name[i] != 0) : (i += 1) {
            if (device.name[i] != name[i]) break;
        }
        if (i == name.len and (i >= 64 or device.name[i] == 0)) {
            return device;
        }
        current = device.next;
    }
    return null;
}

pub fn openDevice(device: *Device) error_handler.Error!void {
    device.ref_count += 1;
    if (device.ops.open) |open_fn| {
        try open_fn(device);
    }
}

pub fn closeDevice(device: *Device) void {
    if (device.ref_count > 0) {
        device.ref_count -= 1;
        if (device.ops.close) |close_fn| {
            close_fn(device);
        }
    }
}

pub fn readDevice(device: *Device, buffer: []u8, offset: usize) error_handler.Error!usize {
    if (device.ops.read) |read_fn| {
        return try read_fn(device, buffer, offset);
    }
    return error_handler.Error.NotImplemented;
}

pub fn writeDevice(device: *Device, buffer: []const u8, offset: usize) error_handler.Error!usize {
    if (device.ops.write) |write_fn| {
        return try write_fn(device, buffer, offset);
    }
    return error_handler.Error.NotImplemented;
}

pub fn ioctlDevice(device: *Device, request: u32, arg: usize) error_handler.Error!i32 {
    if (device.ops.ioctl) |ioctl_fn| {
        return try ioctl_fn(device, request, arg);
    }
    return error_handler.Error.NotImplemented;
}

pub fn getDeviceList() ?*Device {
    return device_list;
}

