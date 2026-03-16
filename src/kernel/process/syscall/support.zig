const abi = @import("abi.zig");
const process = @import("../process.zig");
const protection = @import("../../memory/protection.zig");
const syscall_common = @import("common.zig");
const syscall_cwd = @import("cwd.zig");
const timer = @import("../../timer/timer.zig");

pub const TERMINAL_IO_BUFFER_SIZE: usize = 256;
pub const FILE_IO_BUFFER_SIZE: usize = 4096;
pub const RANDOM_FILL_BUFFER_SIZE: usize = 256;
pub const PROCESS_SLOT_COUNT: usize = process.process_table.len;
pub const PRCTL_NAME_SIZE: usize = 16;
pub const MAX_SIGNAL_NUMBER: usize = 64;

const SYNTHETIC_STATFS_MAGIC: u32 = 0x8584_58F6;
const SYNTHETIC_STATFS_BLOCK_SIZE: u32 = 4096;
const SYNTHETIC_STATFS_TOTAL_BLOCKS: u64 = 1_024 * 1_024;
const SYNTHETIC_STATFS_FREE_BLOCKS: u64 = 512 * 1_024;
const SYNTHETIC_STATFS_TOTAL_FILES: u64 = 65_536;
const SYNTHETIC_STATFS_FREE_FILES: u64 = 32_768;
const SYNTHETIC_STATFS_NAME_LENGTH: u32 = 255;
const SYNTHETIC_SYSINFO_TOTAL_RAM: u32 = 16 * 1024 * 1024;
const SYNTHETIC_SYSINFO_FREE_RAM: u32 = SYNTHETIC_SYSINFO_TOTAL_RAM / 2;

pub const ResolvedUserPathError = error{ InvalidUserPointer, NameTooLong };

pub const StatFs = extern struct {
    f_type: u32,
    f_bsize: u32,
    f_blocks: u64,
    f_bfree: u64,
    f_bavail: u64,
    f_files: u64,
    f_ffree: u64,
    f_fsid: [2]u32,
    f_namelen: u32,
    f_frsize: u32,
    f_flags: u32,
    f_spare: [4]u32,
};

pub const Sysinfo = extern struct {
    uptime: i32,
    loads: [3]u32,
    totalram: u32,
    freeram: u32,
    sharedram: u32,
    bufferram: u32,
    totalswap: u32,
    freeswap: u32,
    procs: u16,
    pad: u16,
    totalhigh: u32,
    freehigh: u32,
    mem_unit: u32,
    _padding: [8]u8,
};

var getrandom_state: u32 = 0xDEADBEEF;

pub fn resolveIoFd(fd: i32) i32 {
    const proc = process.getEffectiveCurrent() orelse return fd;
    return switch (fd) {
        abi.STDIN => proc.stdin_redirect orelse fd,
        abi.STDOUT => proc.stdout_redirect orelse fd,
        abi.STDERR => proc.stderr_redirect orelse fd,
        else => fd,
    };
}

pub fn resolveUserPath(path: []const u8, buffer: *[syscall_common.RESOLVED_PATH_BUFFER_SIZE]u8) ?[]const u8 {
    return syscall_cwd.resolvePath(path, buffer);
}

pub fn processMetadataSlot(pid: u32) usize {
    return @intCast(pid % @as(u32, @intCast(PROCESS_SLOT_COUNT)));
}

pub fn processSlotFromPid(pid: usize) ?usize {
    if (pid >= PROCESS_SLOT_COUNT) return null;
    return pid;
}

pub fn copyUserPathFromAddress(path_addr: usize, kernel_buffer: *[syscall_common.USER_PATH_BUFFER_SIZE]u8) error{InvalidUserPointer}![]const u8 {
    if (!protection.verifyUserPointer(path_addr, syscall_common.USER_PATH_BUFFER_SIZE)) {
        return error.InvalidUserPointer;
    }

    return protection.copyStringFromUser(kernel_buffer, path_addr) catch error.InvalidUserPointer;
}

pub fn copyUserPathFromPointer(pathname: [*]const u8, kernel_buffer: *[syscall_common.USER_PATH_BUFFER_SIZE]u8) error{InvalidUserPointer}![]const u8 {
    return copyUserPathFromAddress(@intFromPtr(pathname), kernel_buffer);
}

pub fn resolveUserPathFromPointer(pathname: [*]const u8, kernel_buffer: *[syscall_common.USER_PATH_BUFFER_SIZE]u8, resolved_buf: *[syscall_common.RESOLVED_PATH_BUFFER_SIZE]u8) ResolvedUserPathError![]const u8 {
    const path_slice = copyUserPathFromPointer(pathname, kernel_buffer) catch {
        return error.InvalidUserPointer;
    };

    return resolveUserPath(path_slice, resolved_buf) orelse error.NameTooLong;
}

pub fn errnoFromResolvedUserPathError(err: ResolvedUserPathError, invalid_errno: i32) i32 {
    return switch (err) {
        error.InvalidUserPointer => invalid_errno,
        error.NameTooLong => abi.ENAMETOOLONG,
    };
}

pub fn rawArgI32(arg: usize) i32 {
    return @as(i32, @bitCast(@as(u32, @truncate(arg))));
}

pub fn rawResultU32(result: i32) u32 {
    return @bitCast(result);
}

pub fn syntheticStatFs() StatFs {
    return .{
        .f_type = SYNTHETIC_STATFS_MAGIC,
        .f_bsize = SYNTHETIC_STATFS_BLOCK_SIZE,
        .f_blocks = SYNTHETIC_STATFS_TOTAL_BLOCKS,
        .f_bfree = SYNTHETIC_STATFS_FREE_BLOCKS,
        .f_bavail = SYNTHETIC_STATFS_FREE_BLOCKS,
        .f_files = SYNTHETIC_STATFS_TOTAL_FILES,
        .f_ffree = SYNTHETIC_STATFS_FREE_FILES,
        .f_fsid = .{ 0, 0 },
        .f_namelen = SYNTHETIC_STATFS_NAME_LENGTH,
        .f_frsize = SYNTHETIC_STATFS_BLOCK_SIZE,
        .f_flags = 0,
        .f_spare = .{ 0, 0, 0, 0 },
    };
}

pub fn syntheticSysinfo() Sysinfo {
    const ticks = timer.getTicks();

    return .{
        .uptime = @intCast(ticks / timer.TICKS_PER_SECOND),
        .loads = [3]u32{ 0, 0, 0 },
        .totalram = SYNTHETIC_SYSINFO_TOTAL_RAM,
        .freeram = SYNTHETIC_SYSINFO_FREE_RAM,
        .sharedram = 0,
        .bufferram = 0,
        .totalswap = 0,
        .freeswap = 0,
        .procs = 1,
        .pad = 0,
        .totalhigh = 0,
        .freehigh = 0,
        .mem_unit = 1,
        ._padding = [_]u8{0} ** 8,
    };
}

pub fn fillRandomBytes(buffer: []u8) void {
    var i: usize = 0;
    while (i + 4 <= buffer.len) : (i += 4) {
        const val = getrandomXorshift();
        buffer[i] = @truncate(val);
        buffer[i + 1] = @truncate(val >> 8);
        buffer[i + 2] = @truncate(val >> 16);
        buffer[i + 3] = @truncate(val >> 24);
    }

    while (i < buffer.len) : (i += 1) {
        buffer[i] = @truncate(getrandomXorshift());
    }
}

fn getrandomXorshift() u32 {
    var x = getrandom_state;
    if (x == 0) {
        x = @truncate(timer.getTicks() | 1);
    }
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    getrandom_state = x;
    return x;
}
