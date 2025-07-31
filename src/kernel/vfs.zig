const std = @import("std");
const memory = @import("memory.zig");
const error_handler = @import("error.zig");

// VFS errors
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
};

// File types
pub const FileType = enum(u8) {
    Regular = 1,
    Directory = 2,
    CharDevice = 3,
    BlockDevice = 4,
    Pipe = 5,
    SymLink = 6,
    Socket = 7,
};

// File permissions (Unix-style)
pub const FileMode = packed struct {
    // Owner permissions
    owner_read: bool = false,
    owner_write: bool = false,
    owner_exec: bool = false,
    
    // Group permissions
    group_read: bool = false,
    group_write: bool = false,
    group_exec: bool = false,
    
    // Other permissions
    other_read: bool = false,
    other_write: bool = false,
    other_exec: bool = false,
    
    // Special bits
    set_uid: bool = false,
    set_gid: bool = false,
    sticky: bool = false,
    
    // Padding
    _padding: u4 = 0,
};

// File information structure
pub const FileStat = struct {
    inode: u64,
    mode: FileMode,
    file_type: FileType,
    size: u64,
    blocks: u64,
    block_size: u32,
    uid: u32,
    gid: u32,
    atime: u64,  // Access time
    mtime: u64,  // Modification time
    ctime: u64,  // Change time
};

// Directory entry
pub const DirEntry = struct {
    name: [256]u8,
    name_len: u16,
    inode: u64,
    file_type: FileType,
};

// File operations
pub const FileOps = struct {
    read: *const fn (*VNode, []u8, u64) VFSError!usize,
    write: *const fn (*VNode, []const u8, u64) VFSError!usize,
    open: *const fn (*VNode, u32) VFSError!void,
    close: *const fn (*VNode) VFSError!void,
    seek: *const fn (*VNode, i64, u32) VFSError!u64,
    ioctl: *const fn (*VNode, u32, usize) VFSError!i32,
    stat: *const fn (*VNode, *FileStat) VFSError!void,
    readdir: *const fn (*VNode, *DirEntry, u64) VFSError!bool,
};

// VNode (Virtual Node) - represents a file/directory in memory
pub const VNode = struct {
    name: [256]u8,
    name_len: u16,
    inode: u64,
    file_type: FileType,
    mode: FileMode,
    size: u64,
    ref_count: u32,
    mount_point: ?*MountPoint,
    parent: ?*VNode,
    children: ?*VNode,
    next_sibling: ?*VNode,
    ops: *const FileOps,
    private_data: ?*anyopaque,
};

// File system operations
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
};

// File system type
pub const FileSystemType = struct {
    name: [32]u8,
    ops: *const FileSystemOps,
    next: ?*FileSystemType,
};

// Mount point
pub const MountPoint = struct {
    device: [256]u8,
    mount_path: [256]u8,
    fs_type: *FileSystemType,
    root: ?*VNode,
    flags: u32,
    private_data: ?*anyopaque,
    next: ?*MountPoint,
};

// Open file descriptor
pub const FileDescriptor = struct {
    vnode: *VNode,
    offset: u64,
    flags: u32,
    ref_count: u32,
};

// File open flags
pub const O_RDONLY: u32 = 0x0000;
pub const O_WRONLY: u32 = 0x0001;
pub const O_RDWR: u32 = 0x0002;
pub const O_CREAT: u32 = 0x0040;
pub const O_EXCL: u32 = 0x0080;
pub const O_TRUNC: u32 = 0x0200;
pub const O_APPEND: u32 = 0x0400;

// Seek constants
pub const SEEK_SET: u32 = 0;
pub const SEEK_CUR: u32 = 1;
pub const SEEK_END: u32 = 2;

// Global VFS state
var root_vnode: ?*VNode = null;
var mount_list: ?*MountPoint = null;
var fs_type_list: ?*FileSystemType = null;
var vnode_cache: [1024]?*VNode = [_]?*VNode{null} ** 1024;
var fd_table: [256]?*FileDescriptor = [_]?*FileDescriptor{null} ** 256;

// Initialize VFS
pub fn init() void {
    // Create root vnode
    root_vnode = createVNode() catch |err| {
        error_handler.handleError(err, "Failed to create root vnode");
        return;
    };
    
    if (root_vnode) |root| {
        root.name[0] = '/';
        root.name[1] = 0;
        root.name_len = 1;
        root.file_type = FileType.Directory;
        root.mode = FileMode{
            .owner_read = true,
            .owner_write = true,
            .owner_exec = true,
            .group_read = true,
            .group_exec = true,
            .other_read = true,
            .other_exec = true,
        };
    }
}

// Register a file system type
pub fn registerFileSystem(fs_type: *FileSystemType) VFSError!void {
    fs_type.next = fs_type_list;
    fs_type_list = fs_type;
}

// Mount a file system
pub fn mount(device: []const u8, mount_path: []const u8, fs_name: []const u8, flags: u32) VFSError!void {
    // Find file system type
    var fs_type = fs_type_list;
    while (fs_type) |fs| : (fs_type = fs.next) {
        if (std.mem.eql(u8, fs.name[0..strlen(&fs.name)], fs_name)) {
            // Create mount point
            const mp = memory.kmalloc(@sizeOf(MountPoint)) orelse return VFSError.OutOfMemory;
            const mount_point = @as(*MountPoint, @ptrCast(@alignCast(mp)));
            
            // Initialize mount point
            @memcpy(mount_point.device[0..device.len], device);
            mount_point.device[device.len] = 0;
            @memcpy(mount_point.mount_path[0..mount_path.len], mount_path);
            mount_point.mount_path[mount_path.len] = 0;
            mount_point.fs_type = fs;
            mount_point.flags = flags;
            mount_point.private_data = null;
            
            // Call file system mount operation
            try fs.ops.mount(mount_point);
            
            // Get root of mounted file system
            mount_point.root = try fs.ops.get_root(mount_point);
            
            // Add to mount list
            mount_point.next = mount_list;
            mount_list = mount_point;
            
            return;
        }
    }
    
    return VFSError.InvalidOperation;
}

// Open a file
pub fn open(path: []const u8, flags: u32) VFSError!u32 {
    const vnode = try lookupPath(path);
    
    // Check if it's a directory
    if (vnode.file_type == FileType.Directory and (flags & O_RDWR) != 0) {
        return VFSError.IsDirectory;
    }
    
    // Call file system open operation
    try vnode.ops.open(vnode, flags);
    
    // Find free file descriptor
    for (fd_table, 0..) |maybe_fd, i| {
        if (maybe_fd == null) {
            const fd_mem = memory.kmalloc(@sizeOf(FileDescriptor)) orelse return VFSError.OutOfMemory;
            const fd = @as(*FileDescriptor, @ptrCast(@alignCast(fd_mem)));
            
            fd.vnode = vnode;
            fd.offset = 0;
            fd.flags = flags;
            fd.ref_count = 1;
            
            fd_table[i] = fd;
            vnode.ref_count += 1;
            
            return @as(u32, @intCast(i));
        }
    }
    
    return VFSError.NoSpace;
}

// Close a file
pub fn close(fd: u32) VFSError!void {
    if (fd >= fd_table.len) return VFSError.InvalidOperation;
    
    if (fd_table[fd]) |file_desc| {
        file_desc.ref_count -= 1;
        if (file_desc.ref_count == 0) {
            try file_desc.vnode.ops.close(file_desc.vnode);
            file_desc.vnode.ref_count -= 1;
            memory.kfree(@as([*]u8, @ptrCast(file_desc)));
            fd_table[fd] = null;
        }
    } else {
        return VFSError.InvalidOperation;
    }
}

// Read from a file
pub fn read(fd: u32, buffer: []u8) VFSError!usize {
    if (fd >= fd_table.len) return VFSError.InvalidOperation;
    
    if (fd_table[fd]) |file_desc| {
        const bytes_read = try file_desc.vnode.ops.read(file_desc.vnode, buffer, file_desc.offset);
        file_desc.offset += bytes_read;
        return bytes_read;
    }
    
    return VFSError.InvalidOperation;
}

// Write to a file
pub fn write(fd: u32, buffer: []const u8) VFSError!usize {
    if (fd >= fd_table.len) return VFSError.InvalidOperation;
    
    if (fd_table[fd]) |file_desc| {
        if ((file_desc.flags & O_WRONLY) == 0 and (file_desc.flags & O_RDWR) == 0) {
            return VFSError.PermissionDenied;
        }
        
        const bytes_written = try file_desc.vnode.ops.write(file_desc.vnode, buffer, file_desc.offset);
        file_desc.offset += bytes_written;
        return bytes_written;
    }
    
    return VFSError.InvalidOperation;
}

// Seek in a file
pub fn seek(fd: u32, offset: i64, whence: u32) VFSError!u64 {
    if (fd >= fd_table.len) return VFSError.InvalidOperation;
    
    if (fd_table[fd]) |file_desc| {
        const new_offset = try file_desc.vnode.ops.seek(file_desc.vnode, offset, whence);
        file_desc.offset = new_offset;
        return new_offset;
    }
    
    return VFSError.InvalidOperation;
}

// Get file statistics
pub fn stat(path: []const u8, stat_buf: *FileStat) VFSError!void {
    const vnode = try lookupPath(path);
    try vnode.ops.stat(vnode, stat_buf);
}

// Read directory entry
pub fn readdir(fd: u32, dirent: *DirEntry, index: u64) VFSError!bool {
    if (fd >= fd_table.len) return VFSError.InvalidOperation;
    
    if (fd_table[fd]) |file_desc| {
        return file_desc.vnode.ops.readdir(file_desc.vnode, dirent, index);
    }
    
    return VFSError.InvalidOperation;
}

// Create a directory
pub fn mkdir(path: []const u8, mode: FileMode) VFSError!void {
    const parent_path = getParentPath(path);
    const name = getBaseName(path);
    
    const parent = try lookupPath(parent_path);
    if (parent.file_type != FileType.Directory) {
        return VFSError.NotDirectory;
    }
    
    _ = try parent.mount_point.?.fs_type.ops.mkdir(parent, name, mode);
}

// Remove a file
pub fn unlink(path: []const u8) VFSError!void {
    const parent_path = getParentPath(path);
    const name = getBaseName(path);
    
    const parent = try lookupPath(parent_path);
    if (parent.file_type != FileType.Directory) {
        return VFSError.NotDirectory;
    }
    
    try parent.mount_point.?.fs_type.ops.unlink(parent, name);
}

// Helper functions
fn createVNode() VFSError!*VNode {
    const vnode_mem = memory.kmalloc(@sizeOf(VNode)) orelse return VFSError.OutOfMemory;
    const vnode = @as(*VNode, @ptrCast(@alignCast(vnode_mem)));
    
    vnode.* = VNode{
        .name = [_]u8{0} ** 256,
        .name_len = 0,
        .inode = 0,
        .file_type = FileType.Regular,
        .mode = FileMode{},
        .size = 0,
        .ref_count = 0,
        .mount_point = null,
        .parent = null,
        .children = null,
        .next_sibling = null,
        .ops = undefined,
        .private_data = null,
    };
    
    return vnode;
}

fn lookupPath(path: []const u8) VFSError!*VNode {
    if (path.len == 0 or path[0] != '/') {
        return VFSError.InvalidPath;
    }
    
    var current = root_vnode orelse return VFSError.NotFound;
    
    if (path.len == 1) {
        return current;
    }
    
    var i: usize = 1;
    while (i < path.len) {
        // Skip multiple slashes
        while (i < path.len and path[i] == '/') : (i += 1) {}
        
        if (i >= path.len) break;
        
        // Find next component
        const start = i;
        while (i < path.len and path[i] != '/') : (i += 1) {}
        
        const component = path[start..i];
        
        // Look up component in current directory
        if (current.mount_point) |mp| {
            current = mp.fs_type.ops.lookup(current, component) catch {
                return VFSError.NotFound;
            };
        } else {
            // Search in vnode children
            var child = current.children;
            var found = false;
            
            while (child) |c| : (child = c.next_sibling) {
                if (std.mem.eql(u8, c.name[0..c.name_len], component)) {
                    current = c;
                    found = true;
                    break;
                }
            }
            
            if (!found) {
                return VFSError.NotFound;
            }
        }
    }
    
    return current;
}

fn getParentPath(path: []const u8) []const u8 {
    var last_slash: usize = 0;
    for (path, 0..) |c, i| {
        if (c == '/') {
            last_slash = i;
        }
    }
    
    if (last_slash == 0) {
        return "/";
    }
    
    return path[0..last_slash];
}

fn getBaseName(path: []const u8) []const u8 {
    var last_slash: usize = 0;
    for (path, 0..) |c, i| {
        if (c == '/') {
            last_slash = i;
        }
    }
    
    return path[last_slash + 1..];
}

fn strlen(str: []const u8) usize {
    var i: usize = 0;
    while (i < str.len and str[i] != 0) : (i += 1) {}
    return i;
}