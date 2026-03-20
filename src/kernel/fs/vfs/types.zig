pub const VFSError = error{
    NotFound,
    PermissionDenied,
    IsDirectory,
    NotDirectory,
    InvalidPath,
    AlreadyExists,
    NoSpace,
    ReadOnly,
    InvalidOperation,
    OutOfMemory,
    DeviceError,
    BrokenPipe,
    TooManyOpenFiles,
    Busy,
};

pub const FileType = enum(u8) {
    Regular = 1,
    Directory = 2,
    CharDevice = 3,
    BlockDevice = 4,
    Pipe = 5,
    SymLink = 6,
    Socket = 7,
};

pub const FileMode = packed struct {
    owner_read: bool = false,
    owner_write: bool = false,
    owner_exec: bool = false,

    group_read: bool = false,
    group_write: bool = false,
    group_exec: bool = false,

    other_read: bool = false,
    other_write: bool = false,
    other_exec: bool = false,

    set_uid: bool = false,
    set_gid: bool = false,
    sticky: bool = false,

    _padding: u4 = 0,
};

pub const FileStat = struct {
    inode: u64,
    mode: FileMode,
    file_type: FileType,
    size: u64,
    blocks: u64,
    block_size: u32,
    uid: u32,
    gid: u32,
    atime: u64,
    mtime: u64,
    ctime: u64,
};

pub const DirEntry = struct {
    name: [256]u8,
    name_len: u16,
    inode: u64,
    file_type: FileType,
};

pub const FileOps = struct {
    read: *const fn (*VNode, []u8, u64) VFSError!usize,
    write: *const fn (*VNode, []const u8, u64) VFSError!usize,
    open: *const fn (*VNode, u32) VFSError!void,
    close: *const fn (*VNode) VFSError!void,
    seek: *const fn (*VNode, i64, u32) VFSError!u64,
    ioctl: *const fn (*VNode, u32, usize) VFSError!i32,
    stat: *const fn (*VNode, *FileStat) VFSError!void,
    readdir: *const fn (*VNode, *DirEntry, u64) VFSError!bool,
    truncate: *const fn (*VNode, u64) VFSError!void,
    chmod: *const fn (*VNode, FileMode) VFSError!void,
    chown: *const fn (*VNode, u32, u32) VFSError!void,
};

pub const VNode = struct {
    name: [256]u8,
    name_len: u16,
    inode: u64,
    file_type: FileType,
    mode: FileMode,
    size: u64,
    uid: u16 = 0,
    gid: u16 = 0,
    ref_count: u32,
    mount_point: ?*MountPoint,
    parent: ?*VNode,
    children: ?*VNode,
    next_sibling: ?*VNode,
    ops: *const FileOps,
    private_data: ?*anyopaque,
};

pub const FileSystemOps = struct {
    mount: *const fn (*MountPoint) VFSError!void,
    unmount: *const fn (*MountPoint) VFSError!void,
    get_root: *const fn (*MountPoint) VFSError!*VNode,
    lookup: *const fn (*VNode, []const u8) VFSError!*VNode,
    create: *const fn (*VNode, []const u8, FileMode) VFSError!*VNode,
    mkdir: *const fn (*VNode, []const u8, FileMode) VFSError!*VNode,
    unlink: *const fn (*VNode, []const u8) VFSError!void,
    rmdir: *const fn (*VNode, []const u8) VFSError!void,
    rename: *const fn (*VNode, []const u8, *VNode, []const u8) VFSError!void,
    symlink: ?*const fn (*VNode, []const u8, []const u8) VFSError!*VNode = null,
    link: ?*const fn (*VNode, []const u8, *VNode) VFSError!void = null,
    readlink: ?*const fn (*VNode, []u8) VFSError!usize = null,
};

pub const FileSystemType = struct {
    name: [32]u8,
    ops: *const FileSystemOps,
    next: ?*FileSystemType,
};

pub const MountPoint = struct {
    device: [256]u8,
    mount_path: [256]u8,
    fs_type: *FileSystemType,
    root: ?*VNode,
    flags: u32,
    ref_count: u32,
    private_data: ?*anyopaque,
    next: ?*MountPoint,
};

pub const FileDescriptor = struct {
    vnode: *VNode,
    offset: u64,
    flags: u32,
    fd_flags: u32,
    ref_count: u32,
    path_len: u16,
    path: [512]u8,
};

pub const MountInfo = struct {
    device: [256]u8 = [_]u8{0} ** 256,
    device_len: u16 = 0,
    mount_path: [256]u8 = [_]u8{0} ** 256,
    mount_path_len: u16 = 0,
    fs_name: [32]u8 = [_]u8{0} ** 32,
    fs_name_len: u8 = 0,
    flags: u32 = 0,
};

pub const O_RDONLY: u32 = 0x0000;
pub const O_WRONLY: u32 = 0x0001;
pub const O_RDWR: u32 = 0x0002;
pub const O_CREAT: u32 = 0x0040;
pub const O_EXCL: u32 = 0x0080;
pub const O_TRUNC: u32 = 0x0200;
pub const O_APPEND: u32 = 0x0400;
pub const O_NONBLOCK: u32 = 0x0800;

pub const SEEK_SET: u32 = 0;
pub const SEEK_CUR: u32 = 1;
pub const SEEK_END: u32 = 2;
