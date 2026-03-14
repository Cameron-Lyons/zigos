const vfs = @import("../../fs/vfs.zig");

pub const USER_PATH_BUFFER_SIZE: usize = 256;
pub const RESOLVED_PATH_BUFFER_SIZE: usize = 512;

pub fn fileModeFromBits(mode: u32) vfs.FileMode {
    return .{
        .owner_read = (mode & 0o400) != 0,
        .owner_write = (mode & 0o200) != 0,
        .owner_exec = (mode & 0o100) != 0,
        .group_read = (mode & 0o040) != 0,
        .group_write = (mode & 0o020) != 0,
        .group_exec = (mode & 0o010) != 0,
        .other_read = (mode & 0o004) != 0,
        .other_write = (mode & 0o002) != 0,
        .other_exec = (mode & 0o001) != 0,
    };
}
